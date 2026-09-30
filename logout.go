package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

const sha256TokenPrefix = "sha256~"

// runLogout revokes cached tokens on the OpenShift OAuth server and removes the cache files.
// Without a server argument, all cached sessions are logged out.
func runLogout(logger *slog.Logger, args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "Usage: openshift-login logout [server]")
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("cannot determine home dir", slog.Any("error", err))
		return 1
	}
	cacheDir := filepath.Join(home, ".kube", "cache", "openshift-login")
	files, err := filepath.Glob(filepath.Join(cacheDir, "*-execCredential.json"))
	if err != nil {
		logger.Error("cannot list cache files", slog.Any("error", err))
		return 1
	}

	var filter *url.URL
	if len(args) == 1 {
		filter, err = parseServer(args[0])
		if err != nil {
			logger.Error("cannot parse server", slog.String("server", args[0]), slog.Any("error", err))
			return 1
		}
	}

	exitCode := 0
	found := false
	for _, cacheFile := range files {
		data, err := os.ReadFile(cacheFile)
		if err != nil {
			logger.Warn("cannot read cache file", slog.String("path", cacheFile), slog.Any("error", err))
			continue
		}
		var cached clientauthenticationv1.ExecCredential
		if err := json.Unmarshal(data, &cached); err != nil || cached.Spec.Cluster == nil {
			logger.Warn("cannot parse cache file", slog.String("path", cacheFile), slog.Any("error", err))
			continue
		}
		server := cached.Spec.Cluster.Server
		if filter != nil {
			u, err := url.Parse(server)
			if err != nil || !matchesServer(filter, u) {
				continue
			}
		}
		found = true

		if cached.Status != nil && cached.Status.Token != "" {
			if err := revokeToken(server, cached.Status.Token); err != nil {
				fmt.Fprintf(os.Stderr, "Could not revoke token on %s, it stays valid until it expires: %v\n", server, err)
				exitCode = 1
			}
		}
		if err := os.Remove(cacheFile); err != nil {
			logger.Error("cannot remove cache file", slog.String("path", cacheFile), slog.Any("error", err))
			exitCode = 1
			continue
		}
		fmt.Printf("Logged out of %s\n", server)
	}

	if !found {
		if filter != nil {
			fmt.Printf("No session found for %s\n", args[0])
		} else {
			fmt.Println("No sessions found")
		}
	}
	return exitCode
}

// parseServer accepts a server URL with or without scheme, e.g. "api.example.com:443".
func parseServer(s string) (*url.URL, error) {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing host")
	}
	return u, nil
}

// matchesServer compares hosts, and ports only if the filter specifies one.
func matchesServer(filter, u *url.URL) bool {
	if !strings.EqualFold(filter.Hostname(), u.Hostname()) {
		return false
	}
	return filter.Port() == "" || filter.Port() == u.Port()
}

// revokeToken deletes the OAuth access token on the server, the same way `oc logout` does.
func revokeToken(server, token string) error {
	// sha256~ tokens are stored under the hash of the token, not the token itself
	name := token
	if strings.HasPrefix(token, sha256TokenPrefix) {
		h := sha256.Sum256([]byte(strings.TrimPrefix(token, sha256TokenPrefix)))
		name = sha256TokenPrefix + base64.RawURLEncoding.EncodeToString(h[:])
	}
	client := &http.Client{Timeout: 10 * time.Second}
	status := 0
	// useroauthaccesstokens lets users delete their own tokens, fall back to oauthaccesstokens on older clusters
	for _, resource := range []string{"useroauthaccesstokens", "oauthaccesstokens"} {
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/apis/oauth.openshift.io/v1/%s/%s", strings.TrimSuffix(server, "/"), resource, url.PathEscape(name)), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		status = resp.StatusCode
		switch status {
		case http.StatusOK, http.StatusAccepted, http.StatusUnauthorized:
			// 401: the token is already expired or revoked
			return nil
		case http.StatusNotFound, http.StatusForbidden:
			continue
		default:
			return fmt.Errorf("unexpected status %d", status)
		}
	}
	if status == http.StatusNotFound {
		// the token does not exist (anymore)
		return nil
	}
	return fmt.Errorf("not allowed to delete token (status %d)", status)
}

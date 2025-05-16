package main

import (
	"context"
	"crypto/rand"
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

	"github.com/int128/oauth2cli"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// sanitize turns any non‐letter/digit into '-'
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

func tokenRequestOptions(p string) (o []oauth2.AuthCodeOption) {
	if p != "" {
		o = append(o, oauth2.VerifierOption(p))
	}
	return
}

func RandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("unable to get random bytes: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func main() {
	logLevelStr := os.Getenv("OPENSHIFT_LOGIN_LOGLEVEL")
	var logLevel slog.Level
	switch strings.ToLower(logLevelStr) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning", "":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelWarn
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	env := os.Getenv("KUBERNETES_EXEC_INFO")
	if env == "" {
		logger.Error("KUBERNETES_EXEC_INFO is not set")
		return
	}
	var execCredential clientauthenticationv1.ExecCredential
	if err := json.Unmarshal([]byte(env), &execCredential); err != nil {
		logger.Error("Error unmarshalling KUBERNETES_EXEC_INFO", slog.Any("error", err))
		return
	}
	if execCredential.Spec.Cluster != nil {
		home, err := os.UserHomeDir()
		if err == nil {
			u, err := url.Parse(execCredential.Spec.Cluster.Server)
			if err == nil {
				name := sanitize(u.Host)
				cacheDir := filepath.Join(home, ".kube", "cache", "openshift-login")
				cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s-execCredential.json", name))
				logger.Info("Checking for cached credentials", slog.String("path", cacheFile))
				if data, err := os.ReadFile(cacheFile); err == nil {
					logger.Info("Found cache file, attempting to unmarshal")
					var cached clientauthenticationv1.ExecCredential
					if err := json.Unmarshal(data, &cached); err == nil &&
						cached.Status != nil &&
						cached.Status.ExpirationTimestamp != nil &&
						cached.Status.ExpirationTimestamp.After(time.Now()) {
						logger.Info("Cache is not expired, checking with Kubernetes API")
						// Check with Kubernetes API if token is still valid
						req, err := http.NewRequest("GET", execCredential.Spec.Cluster.Server+"/api", nil)
						if err == nil {
							req.Header.Set("Authorization", "Bearer "+cached.Status.Token)
							client := &http.Client{Timeout: 5 * time.Second}
							resp, err := client.Do(req)
							if err == nil {
								defer resp.Body.Close()
								if resp.StatusCode == 200 {
									logger.Info("Cache is valid, returning cached credentials")
									fmt.Println(string(data))
									return
								} else if resp.StatusCode == 401 {
									logger.Warn("Cached token rejected by API, ignoring cache", slog.Int("status", resp.StatusCode))
								} else {
									logger.Warn("Unexpected status from API, ignoring cache", slog.Int("status", resp.StatusCode))
								}
							} else {
								logger.Warn("Error contacting Kubernetes API, ignoring cache", slog.Any("error", err))
							}
						} else {
							logger.Warn("Error creating request to Kubernetes API, ignoring cache", slog.Any("error", err))
						}
					} else {
						logger.Info("Cache is invalid or expired")
					}
				} else {
					logger.Info("No valid cache file found", slog.Any("error", err))
				}
			} else {
				logger.Warn("Failed to parse cluster server URL", slog.Any("error", err))
			}
		} else {
			logger.Warn("Failed to determine home directory", slog.Any("error", err))
		}
	}
	oidcDiscoveryURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", execCredential.Spec.Cluster.Server)
	logger.Info("OIDC Discovery URL", slog.String("url", oidcDiscoveryURL))

	resp, err := http.Get(oidcDiscoveryURL)
	if err != nil {
		logger.Error("Error getting OIDC discovery URL", slog.Any("error", err))
		return
	}
	defer resp.Body.Close()
	var oidcDiscoveryMap map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&oidcDiscoveryMap); err != nil {
		logger.Error("Error decoding OIDC discovery response", slog.Any("error", err))
		return
	}
	authEndpoint, ok := oidcDiscoveryMap["authorization_endpoint"].(string)
	if !ok {
		logger.Error("authorization_endpoint not found in OIDC discovery response")
		return
	}
	tokenEndpoint, ok := oidcDiscoveryMap["token_endpoint"].(string)
	if !ok {
		logger.Error("token_endpoint not found in OIDC discovery response")
		return
	}

	p := oauth2.GenerateVerifier()
	ready := make(chan string, 1)
	defer close(ready)
	cfg := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			ClientID: "openshift-cli-client",
			Endpoint: oauth2.Endpoint{
				AuthURL:  authEndpoint,
				TokenURL: tokenEndpoint,
			},
		},
		AuthCodeOptions: []oauth2.AuthCodeOption{
			oauth2.S256ChallengeOption(p),
		},
		RedirectURLHostname:     "127.0.0.1",
		LocalServerBindAddress:  []string{"127.0.0.1:33831"},
		LocalServerCallbackPath: "/callback",
		TokenRequestOptions:     tokenRequestOptions(p),
		LocalServerReadyChan:    ready,
	}

	ctx := context.Background()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		select {
		case url := <-ready:
			logger.Info("Open browser for authentication", slog.String("url", url))
			if err := browser.OpenURL(url); err != nil {
				logger.Warn("Could not open the browser", slog.Any("error", err))
			}
			return nil
		case <-ctx.Done():
			return fmt.Errorf("context done while waiting for authorization: %w", ctx.Err())
		}
	})
	var token *oauth2.Token
	eg.Go(func() error {
		tok, err := oauth2cli.GetToken(ctx, cfg)
		if err != nil {
			return fmt.Errorf("could not get a token: %w", err)
		}
		token = tok
		logger.Info("You got a valid token", slog.Time("expiry", token.Expiry))
		return nil
	})
	if err := eg.Wait(); err != nil {
		logger.Error("authorization error", slog.Any("error", err))
		return
	}

	execCredential.Status = &clientauthenticationv1.ExecCredentialStatus{
		Token:               token.AccessToken,
		ExpirationTimestamp: &metav1.Time{Time: token.Expiry},
	}
	output, err := json.Marshal(execCredential)
	if err != nil {
		logger.Error("Error marshalling ExecCredential", slog.Any("error", err))
		return
	}
	fmt.Println(string(output))

	// --- begin cache logic ---
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("cannot determine home dir", slog.Any("error", err))
		return
	}
	// parse cluster server URL
	u, err := url.Parse(execCredential.Spec.Cluster.Server)
	if err != nil {
		logger.Error("cannot parse cluster server URL", slog.Any("error", err))
		return
	}
	// sanitize host:port into a safe directory name
	name := sanitize(u.Host)
	cacheDir := filepath.Join(home, ".kube", "cache", "openshift-login")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		logger.Error("cannot create cache dir", slog.Any("error", err))
		return
	}
	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s-execCredential.json", name))
	if err := os.WriteFile(cacheFile, output, 0600); err != nil {
		logger.Warn("cannot write cache file", slog.Any("error", err))
	} else {
		logger.Info("cached execCredential", slog.String("path", cacheFile))
	}
	// --- end cache logic ---
}

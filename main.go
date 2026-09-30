package main

import (
	"bufio"
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
		logLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	idp := strings.TrimSpace(os.Getenv("OPENSHIFT_LOGIN_IDP"))
	env := os.Getenv("KUBERNETES_EXEC_INFO")
	if env == "" {
		logger.Error("KUBERNETES_EXEC_INFO is not set")
		os.Exit(1)
	}
	var execCredential clientauthenticationv1.ExecCredential
	if err := json.Unmarshal([]byte(env), &execCredential); err != nil {
		logger.Error("Error unmarshalling KUBERNETES_EXEC_INFO", slog.Any("error", err))
		os.Exit(1)
	}
	if execCredential.Spec.Cluster != nil {
		home, err := os.UserHomeDir()
		if err == nil {
			u, err := url.Parse(execCredential.Spec.Cluster.Server)
			if err == nil {
				name := sanitize(u.Host)
				cacheDir := filepath.Join(home, ".kube", "cache", "openshift-login")
				cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s-execCredential.json", name))
				logger.Debug("Checking for cached credentials", slog.String("path", cacheFile))
				if data, err := os.ReadFile(cacheFile); err == nil {
					logger.Debug("Found cache file, attempting to unmarshal")
					var cached clientauthenticationv1.ExecCredential
					if err := json.Unmarshal(data, &cached); err == nil &&
						cached.Status != nil &&
						cached.Status.ExpirationTimestamp != nil &&
						cached.Status.ExpirationTimestamp.After(time.Now()) {
						logger.Debug("Cache is not expired, checking with Kubernetes API")
						// Check with Kubernetes API if token is still valid
						req, err := http.NewRequest("GET", execCredential.Spec.Cluster.Server+"/api", nil)
						if err == nil {
							req.Header.Set("Authorization", "Bearer "+cached.Status.Token)
							client := &http.Client{Timeout: 5 * time.Second}
							resp, err := client.Do(req)
							if err == nil {
								defer resp.Body.Close()
								if resp.StatusCode == 200 {
									logger.Debug("Cache is valid, returning cached credentials")
									fmt.Println(string(data))
									os.Exit(0)
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
						logger.Debug("Cache is invalid or expired")
					}
				} else {
					logger.Debug("No valid cache file found", slog.Any("error", err))
				}
			} else {
				logger.Warn("Failed to parse cluster server URL", slog.Any("error", err))
			}
		} else {
			logger.Warn("Failed to determine home directory", slog.Any("error", err))
		}
	}

	// exit if not interactive
	if !execCredential.Spec.Interactive {
		logger.Error("Not executed interactivly, exiting. Please start interactive authentication process from a terminal.")
		os.Exit(1)
	}

	oidcDiscoveryURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", execCredential.Spec.Cluster.Server)
	logger.Debug("OIDC Discovery URL", slog.String("url", oidcDiscoveryURL))

	resp, err := http.Get(oidcDiscoveryURL)
	if err != nil {
		logger.Error("Error getting OIDC discovery URL", slog.Any("error", err))
		os.Exit(1)
	}
	defer resp.Body.Close()
	var oidcDiscoveryMap map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&oidcDiscoveryMap); err != nil {
		logger.Error("Error decoding OIDC discovery response", slog.Any("error", err))
		os.Exit(1)
	}
	authEndpoint, ok := oidcDiscoveryMap["authorization_endpoint"].(string)
	if !ok {
		logger.Error("authorization_endpoint not found in OIDC discovery response")
		os.Exit(1)
	}
	tokenEndpoint, ok := oidcDiscoveryMap["token_endpoint"].(string)
	if !ok {
		logger.Error("token_endpoint not found in OIDC discovery response")
		os.Exit(1)
	}

	if idp != "" {
		logger.Debug("Setting idp query parameter to skip identity provider chooser", slog.String("idp", idp))
	}
	cfg := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			ClientID: "openshift-cli-client",
			Endpoint: oauth2.Endpoint{
				AuthURL:  authEndpoint,
				TokenURL: tokenEndpoint,
			},
		},
		RedirectURLHostname:     "127.0.0.1",
		LocalServerBindAddress:  []string{"127.0.0.1:33831"},
		LocalServerCallbackPath: "/callback",
		Logf:                    logger.Debug,
	}

	// A failed login (e.g. the browser window is logged in as the wrong user) stops the
	// local server. Restart it on the same URL so the login can be retried in another window.
	ctx := context.Background()

	// On a terminal the browser only opens after pressing Enter, so the URL can be opened in
	// another browser window instead, e.g. one that is logged in as the right user.
	var enter chan struct{}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		enter = make(chan struct{})
		go func() {
			r := bufio.NewReader(os.Stdin)
			for {
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				enter <- struct{}{}
			}
		}()
	}
	openBrowser := func(url string) {
		if err := browser.OpenURL(url); err != nil {
			logger.Warn("Could not open the browser", slog.Any("error", err))
		}
	}
	loginURL := ""
	var token *oauth2.Token
	for attempt := 1; token == nil; attempt++ {
		p := oauth2.GenerateVerifier()
		cfg.AuthCodeOptions = []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(p)}
		if idp != "" {
			cfg.AuthCodeOptions = append(cfg.AuthCodeOptions, oauth2.SetAuthURLParam("idp", idp))
		}
		cfg.TokenRequestOptions = tokenRequestOptions(p)
		ready := make(chan string, 1)
		cfg.LocalServerReadyChan = ready

		type result struct {
			token *oauth2.Token
			err   error
		}
		done := make(chan result, 1)
		go func(cfg oauth2cli.Config) {
			tok, err := oauth2cli.GetToken(ctx, cfg)
			done <- result{tok, err}
		}(cfg)

		started := false
		var res result
	wait:
		for {
			select {
			case url := <-ready:
				started = true
				loginURL = url
				// stdout is reserved for the ExecCredential, so print the URL to stderr
				switch {
				case attempt > 1:
					fmt.Fprintf(os.Stderr, "Waiting for login. Open this URL in the correct browser window (Ctrl+C to abort):\n\n    %s\n\n", url)
				case enter != nil:
					fmt.Fprintf(os.Stderr, "Open this URL in the browser window you want to log in with:\n\n    %s\n\nOr press Enter to open it in the default browser.\n", url)
				default:
					fmt.Fprintf(os.Stderr, "Opening browser for authentication. If the wrong browser window opens, open this URL manually:\n\n    %s\n\n", url)
					openBrowser(url)
				}
			case <-enter:
				if loginURL != "" {
					openBrowser(loginURL)
				}
			case res = <-done:
				break wait
			}
		}
		// the ready URL is buffered, so it may still be pending when the result arrives
		select {
		case <-ready:
			started = true
		default:
		}

		if res.err == nil {
			token = res.token
			logger.Debug("You got a valid token", slog.Time("expiry", token.Expiry))
			break
		}
		if !started {
			// the local server could not be started, retrying will not help
			logger.Error("authorization error", slog.Any("error", res.err))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", res.err)
	}

	execCredential.Status = &clientauthenticationv1.ExecCredentialStatus{
		Token:               token.AccessToken,
		ExpirationTimestamp: &metav1.Time{Time: token.Expiry},
	}
	output, err := json.Marshal(execCredential)
	if err != nil {
		logger.Error("Error marshalling ExecCredential", slog.Any("error", err))
		os.Exit(1)
	}
	fmt.Println(string(output))

	// --- begin cache logic ---
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("cannot determine home dir", slog.Any("error", err))
		os.Exit(1)
	}
	// parse cluster server URL
	u, err := url.Parse(execCredential.Spec.Cluster.Server)
	if err != nil {
		logger.Error("cannot parse cluster server URL", slog.Any("error", err))
		os.Exit(1)
	}
	// sanitize host:port into a safe directory name
	name := sanitize(u.Host)
	cacheDir := filepath.Join(home, ".kube", "cache", "openshift-login")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		logger.Error("cannot create cache dir", slog.Any("error", err))
		os.Exit(1)
	}
	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s-execCredential.json", name))
	if err := os.WriteFile(cacheFile, output, 0600); err != nil {
		logger.Warn("cannot write cache file", slog.Any("error", err))
	} else {
		logger.Debug("cached execCredential", slog.String("path", cacheFile))
	}
	// --- end cache logic ---
}

//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/unixcrypt"
)

// TestSystemAccountLoginLinuxIntegration logs in with real host accounts:
// it creates throwaway users with useradd/chpasswd (so the hashes come from
// the system's own libcrypt), signs in through the panel handler over TLS,
// and changes the accounts with the usual tools to see sessions end. It
// needs root and VEER_RUN_SYSTEM_ACCOUNT_TEST=1, and removes the users when
// it finishes.
func TestSystemAccountLoginLinuxIntegration(t *testing.T) {
	if os.Getenv("VEER_RUN_SYSTEM_ACCOUNT_TEST") != "1" {
		t.Skip("set VEER_RUN_SYSTEM_ACCOUNT_TEST=1 to create temporary host accounts")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, tool := range []string{"useradd", "userdel", "chpasswd", "usermod", "chage", "gpasswd", "getent"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	adminGroup := ""
	for _, group := range []string{"sudo", "wheel"} {
		if exec.Command("getent", "group", group).Run() == nil {
			adminGroup = group
			break
		}
	}
	if adminGroup == "" {
		t.Skip("neither sudo nor wheel exists")
	}

	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
	}
	setPassword := func(user, password, method string) {
		t.Helper()
		args := []string{}
		if method != "" {
			args = append(args, "-c", method)
		}
		cmd := exec.Command("chpasswd", args...)
		cmd.Stdin = strings.NewReader(user + ":" + password + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("chpasswd %s: %v\n%s", method, err, out)
		}
	}
	suffix := fmt.Sprintf("%d", os.Getpid()%100000)
	admin := "veertestadm" + suffix
	plain := "veertestusr" + suffix
	for _, user := range []string{admin, plain} {
		run("useradd", "-M", "-s", "/usr/sbin/nologin", user)
		user := user
		t.Cleanup(func() {
			if out, err := exec.Command("userdel", user).CombinedOutput(); err != nil {
				t.Errorf("userdel %s: %v\n%s", user, err, out)
			}
			if exec.Command("getent", "passwd", user).Run() == nil {
				t.Errorf("test account %s still exists", user)
			}
		})
	}
	run("usermod", "-aG", adminGroup, admin)
	const password = "Corr3ct-horse battery"
	setPassword(admin, password, "") // the system default: yescrypt on Debian 12
	setPassword(plain, password, "")

	store := newSystemAccountStore(defaultSystemAccountFiles)
	shadowHash := func(user string) string {
		t.Helper()
		snapshot, err := readSystemAccountSnapshot(defaultSystemAccountFiles)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot.shadow[user].hash
	}
	hash := shadowHash(admin)
	t.Logf("default hash scheme of this host: %s (%s...)", unixcrypt.Scheme(hash), hash[:min(len(hash), 10)])
	if unixcrypt.Scheme(hash) == "" {
		t.Fatalf("unsupported default hash %q", hash)
	}
	if root, reason, err := store.account("root", systemLoginPolicy{rootLogin: true}); err != nil || root == nil || root.uid != 0 {
		t.Fatalf("root from the real files: %+v %q %v", root, reason, err)
	}

	cfg := &Config{
		WebToken:             "integration-web-token-0123456789",
		WebAuthRealmsSetting: []string{webAuthRealmSystem, webAuthRealmToken},
	}
	var logs bytes.Buffer
	auth := newWebAuth(cfg, openTestDB(t), &ProcessManager{}, webAuthOptions{logf: func(format string, args ...any) {
		fmt.Fprintf(&logs, format+"\n", args...)
	}})
	server := httptest.NewUnstartedServer(buildAPIHandlerWithAuth(cfg, auth.revoked.db, &ProcessManager{}, auth))
	server.StartTLS()
	defer server.Close()
	// A remote-looking client: the TLS connection is what allows the
	// password, not the loopback address (the plain listener is checked
	// separately below).
	jar, _ := cookiejar.New(nil)
	client := server.Client()
	client.Jar = jar

	login := func(user, pw string) (*http.Response, webSessionView) {
		t.Helper()
		body, _ := json.Marshal(webLoginRequest{Realm: webAuthRealmSystem, Username: user, Password: pw})
		resp, err := client.Post(server.URL+webAuthLoginPath, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var view webSessionView
		_ = json.NewDecoder(resp.Body).Decode(&view)
		return resp, view
	}
	get := func(path string) *http.Response {
		t.Helper()
		resp, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	start := time.Now()
	resp, view := login(admin, password)
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusOK || view.Identity == nil || view.Identity.Name != admin+"@system" {
		t.Fatalf("admin login over TLS: %d %+v\n%s", resp.StatusCode, view, logs.String())
	}
	t.Logf("%s login took %s", unixcrypt.Scheme(hash), elapsed)
	var sessionCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == webSessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie over TLS = %+v", sessionCookie)
	}
	if resp := get("/api/tags"); resp.StatusCode != http.StatusOK {
		t.Fatalf("API with the session: %d", resp.StatusCode)
	}
	if resp, _ := login(admin, password+"x"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	if resp, _ := login(plain, password); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-administrator: %d", resp.StatusCode)
	}

	expectSessionEnded := func(step, reason string) {
		t.Helper()
		auth.accounts.invalidate() // do not wait for the 30 s re-read
		resp := get("/api/tags")
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(webAuthReasonHeader) != reason {
			t.Fatalf("%s: %d %q, want 401 %s", step, resp.StatusCode, resp.Header.Get(webAuthReasonHeader), reason)
		}
	}

	// passwd: the old session ends, the new password works.
	setPassword(admin, password+"2", "")
	expectSessionEnded("after a password change", webSessionCredentialsChanged)
	if resp, _ := login(admin, password); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password after the change: %d", resp.StatusCode)
	}
	if resp, _ := login(admin, password+"2"); resp.StatusCode != http.StatusOK {
		t.Fatalf("new password: %d\n%s", resp.StatusCode, logs.String())
	}

	// usermod -L
	run("usermod", "-L", admin)
	expectSessionEnded("after usermod -L", webSessionAccountRefused)
	if resp, _ := login(admin, password+"2"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("locked account: %d", resp.StatusCode)
	}
	run("usermod", "-U", admin)

	// chage -E 0: the account expired.
	if resp, _ := login(admin, password+"2"); resp.StatusCode != http.StatusOK {
		t.Fatalf("unlocked account: %d", resp.StatusCode)
	}
	run("chage", "-E", "0", admin)
	expectSessionEnded("after chage -E 0", webSessionAccountRefused)
	if resp, _ := login(admin, password+"2"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired account: %d", resp.StatusCode)
	}
	run("chage", "-E", "-1", admin)

	// passwd -e: the password must be changed first.
	run("chage", "-d", "0", admin)
	if resp, _ := login(admin, password+"2"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password marked expired: %d", resp.StatusCode)
	}
	run("chage", "-d", time.Now().Format("2006-01-02"), admin)

	// Leaving the administrator group ends the session.
	if resp, _ := login(admin, password+"2"); resp.StatusCode != http.StatusOK {
		t.Fatalf("restored account: %d\n%s", resp.StatusCode, logs.String())
	}
	run("gpasswd", "-d", admin, adminGroup)
	expectSessionEnded("after leaving "+adminGroup, webSessionAccountRefused)
	run("usermod", "-aG", adminGroup, admin)

	// Other hash schemes the host's chpasswd can write.
	current := password + "2"
	for _, method := range []string{"SHA512", "SHA256", "MD5", "YESCRYPT"} {
		cmd := exec.Command("chpasswd", "-c", method)
		cmd.Stdin = strings.NewReader(admin + ":" + password + "-" + method + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("chpasswd -c %s unsupported here: %s", method, strings.TrimSpace(string(out)))
			continue
		}
		scheme := unixcrypt.Scheme(shadowHash(admin))
		auth.accounts.invalidate()
		if resp, _ := login(admin, password+"-"+method); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s (%s) login: %d\n%s", method, scheme, resp.StatusCode, logs.String())
		}
		if resp, _ := login(admin, password); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s wrong password: %d", method, resp.StatusCode)
		}
		current = password + "-" + method
		t.Logf("chpasswd -c %s wrote %s: login ok", method, scheme)
	}

	// The same handler over plain HTTP: loopback is allowed, a forwarded
	// request from an untrusted local proxy is not.
	plainServer := httptest.NewServer(buildAPIHandlerWithAuth(cfg, auth.revoked.db, &ProcessManager{}, auth))
	defer plainServer.Close()
	body, _ := json.Marshal(webLoginRequest{Realm: webAuthRealmSystem, Username: admin, Password: current})
	resp, err := http.Post(plainServer.URL+webAuthLoginPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loopback plain HTTP login: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, plainServer.URL+webAuthLoginPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("relayed plain HTTP login: %d", resp.StatusCode)
	}

	text := logs.String()
	for _, want := range []string{"auth: login accepted client=127.0.0.1 realm=system user=" + admin, "reason=bad_password", "reason=not_admin", "reason=locked", "reason=account_expired", "reason=password_expired", "reason=insecure_channel"} {
		if !strings.Contains(text, want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, password) {
		t.Fatal("log contains a password")
	}
}

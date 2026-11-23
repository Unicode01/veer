package app

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Known hashes of "Hello world!" (see internal/unixcrypt).
const (
	testHashMD5    = "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1"
	testHashSHA512 = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
	testHashYes    = "$y$j75$saltsaltsaltsaltsalt..$yV5eLO3gNlU9v6pzxkwgPk44iniP5.vzmlDY/bGIA53"
	testPassword   = "Hello world!"
)

var testAccountsNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func testShadowDay(offset int64) string {
	return strconv.FormatInt(testAccountsNow.Unix()/86400+offset, 10)
}

func writeTestAccountFiles(t *testing.T, dir, passwd, shadow, group string) systemAccountFiles {
	t.Helper()
	files := systemAccountFiles{
		passwd: filepath.Join(dir, "passwd"),
		shadow: filepath.Join(dir, "shadow"),
		group:  filepath.Join(dir, "group"),
	}
	for path, data := range map[string]string{files.passwd: passwd, files.shadow: shadow, files.group: group} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func standardTestAccounts(t *testing.T, dir string) systemAccountFiles {
	day := testShadowDay(-10)
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"toor:x:0:0:second root:/root:/bin/sh\n" +
		"alice:x:1000:1000::/home/alice:/bin/bash\n" +
		"bob:x:1001:10::/home/bob:/bin/bash\n" +
		"carol:x:1002:1002::/home/carol:/bin/bash\n" +
		"dave:x:1003:1003::/home/dave:/bin/bash\n" +
		"locked:x:1004:1004::/:/bin/sh\n" +
		"nopass:x:1005:1005::/:/bin/sh\n" +
		"expired:x:1006:1006::/:/bin/sh\n" +
		"zero:x:1007:1007::/:/bin/sh\n" +
		"mustchange:x:1008:1008::/:/bin/sh\n" +
		"aged:x:1009:1009::/:/bin/sh\n" +
		"inactive:x:1010:1010::/:/bin/sh\n" +
		"des:x:1011:1011::/:/bin/sh\n" +
		"bang:x:1012:1012::/:/bin/sh\n" +
		"future:x:1013:1013::/:/bin/sh\n" +
		"noshadow:x:1014:1014::/:/bin/sh\n" +
		"+nisuser::::::\n"
	shadow := "root:" + testHashSHA512 + ":" + day + ":0:99999:7:::\n" +
		"toor:" + testHashMD5 + ":" + day + ":0:99999:7:::\n" +
		"alice:" + testHashYes + ":" + day + ":0:99999:7:::\n" +
		"bob:" + testHashMD5 + ":" + day + "::::::\n" +
		"carol:" + testHashMD5 + ":" + day + ":0:99999:7:::\n" +
		"dave:" + testHashMD5 + ":" + day + ":0:99999:7:::\n" +
		"locked:!" + testHashMD5 + ":" + day + ":0:99999:7:::\n" +
		"nopass::" + day + ":0:99999:7:::\n" +
		"expired:" + testHashMD5 + ":" + day + ":0:99999:7::" + testShadowDay(-1) + ":\n" +
		"zero:" + testHashMD5 + ":" + day + ":0:99999:7::0:\n" +
		"mustchange:" + testHashMD5 + ":0:0:99999:7:::\n" +
		"aged:" + testHashMD5 + ":" + testShadowDay(-100) + ":0:30:7:::\n" +
		"inactive:" + testHashMD5 + ":" + testShadowDay(-100) + ":0:30:7:5::\n" +
		"des:abJnggxhB/yWI:" + day + ":0:99999:7:::\n" +
		"bang:*:" + day + ":0:99999:7:::\n" +
		"future:" + testHashMD5 + ":" + day + ":0:99999:7::" + testShadowDay(30) + ":\n"
	group := "root:x:0:\n" +
		"wheel:x:10:\n" +
		"sudo:x:27:alice,locked,nopass,expired,zero,mustchange,aged,inactive,des,bang,future\n" +
		"admins:x:500:dave\n" +
		"carol:x:1002:\n"
	return writeTestAccountFiles(t, dir, passwd, shadow, group)
}

func TestSystemAccountAdministratorPolicy(t *testing.T) {
	store := newSystemAccountStore(standardTestAccounts(t, t.TempDir()))
	store.now = func() time.Time { return testAccountsNow }
	defaults := systemLoginPolicy{adminGroups: defaultWebAdminGroups, rootLogin: true}
	for _, tc := range []struct {
		user   string
		policy systemLoginPolicy
		want   string
	}{
		{"root", defaults, ""},
		{"toor", defaults, ""},                   // any uid 0 account
		{"alice", defaults, ""},                  // listed in sudo
		{"bob", defaults, ""},                    // primary group wheel
		{"carol", defaults, systemLoginNotAdmin}, // no admin group
		{"dave", defaults, systemLoginNotAdmin},
		{"dave", systemLoginPolicy{adminGroups: []string{"admins"}, rootLogin: true}, ""},
		{"root", systemLoginPolicy{adminGroups: defaultWebAdminGroups}, systemLoginRootDisabled},
		{"toor", systemLoginPolicy{adminGroups: defaultWebAdminGroups}, systemLoginRootDisabled},
		{"alice", systemLoginPolicy{adminGroups: defaultWebAdminGroups}, ""},
		{"alice", systemLoginPolicy{adminGroups: nil, rootLogin: true}, systemLoginNotAdmin},
		{"root", systemLoginPolicy{adminGroups: nil, rootLogin: true}, ""},
		{"nobody", defaults, systemLoginUnknownUser},
		{"noshadow", defaults, systemLoginUnknownUser},
		{"+nisuser", defaults, systemLoginInvalidUser},
		{"root:x", defaults, systemLoginInvalidUser},
		{"ro ot", defaults, systemLoginInvalidUser},
		{"", defaults, systemLoginInvalidUser},
	} {
		_, reason, err := store.account(tc.user, tc.policy)
		if err != nil {
			t.Fatalf("account(%q): %v", tc.user, err)
		}
		if reason != tc.want {
			t.Errorf("account(%q, %+v) reason = %q, want %q", tc.user, tc.policy, reason, tc.want)
		}
	}
}

func TestSystemAccountShadowStates(t *testing.T) {
	store := newSystemAccountStore(standardTestAccounts(t, t.TempDir()))
	store.now = func() time.Time { return testAccountsNow }
	policy := systemLoginPolicy{adminGroups: defaultWebAdminGroups, rootLogin: true}
	for user, want := range map[string]string{
		"locked":     systemLoginLocked,
		"bang":       systemLoginLocked,
		"nopass":     systemLoginNoPassword,
		"expired":    systemLoginAccountExpired,
		"zero":       systemLoginAccountExpired, // chage -E 0, as pam_unix reads it
		"mustchange": systemLoginPasswordExpired,
		"aged":       systemLoginPasswordExpired,
		"inactive":   systemLoginAccountInactive,
		"des":        systemLoginUnsupportedHash,
		"future":     "",
	} {
		_, reason, err := store.account(user, policy)
		if err != nil {
			t.Fatal(err)
		}
		if reason != want {
			t.Errorf("account(%q) reason = %q, want %q", user, reason, want)
		}
	}
}

func TestSystemAccountPasswordVerification(t *testing.T) {
	store := newSystemAccountStore(standardTestAccounts(t, t.TempDir()))
	store.now = func() time.Time { return testAccountsNow }
	policy := systemLoginPolicy{adminGroups: defaultWebAdminGroups, rootLogin: true}
	for _, user := range []string{"root", "toor", "alice", "bob"} {
		account, reason, err := store.account(user, policy)
		if err != nil || reason != "" {
			t.Fatalf("account(%q) = %q, %v", user, reason, err)
		}
		if got := verifySystemPassword(account, testPassword); got != "" {
			t.Errorf("%s: correct password refused: %s", user, got)
		}
		if got := verifySystemPassword(account, "hello world!"); got != systemLoginBadPassword {
			t.Errorf("%s: wrong password = %q", user, got)
		}
		if got := verifySystemPassword(account, ""); got != systemLoginEmptyPassword {
			t.Errorf("%s: empty password = %q", user, got)
		}
	}
}

func TestSystemAccountStoreRereadsChangedFiles(t *testing.T) {
	dir := t.TempDir()
	files := standardTestAccounts(t, dir)
	now := testAccountsNow
	store := newSystemAccountStore(files)
	store.now = func() time.Time { return now }
	policy := systemLoginPolicy{adminGroups: defaultWebAdminGroups, rootLogin: true}
	if _, reason, _ := store.account("carol", policy); reason != systemLoginNotAdmin {
		t.Fatalf("carol before = %q", reason)
	}
	if err := os.WriteFile(files.group, []byte("sudo:x:27:alice,carol\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same second, maybe same mtime: the size differs, so it is read again.
	if _, reason, _ := store.account("carol", policy); reason != "" {
		t.Fatalf("carol after joining sudo = %q", reason)
	}
	// A change that keeps size and mtime is picked up after the reload gap.
	info, _ := os.Stat(files.group)
	if err := os.WriteFile(files.group, []byte("sudo:x:27:alice,carlo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(files.group, info.ModTime(), info.ModTime())
	if _, reason, _ := store.account("carol", policy); reason != "" {
		t.Fatalf("carol within the reload gap = %q, want the cached answer", reason)
	}
	now = now.Add(systemAccountFileReloadGap)
	if _, reason, _ := store.account("carol", policy); reason != systemLoginNotAdmin {
		t.Fatalf("carol after the reload gap = %q", reason)
	}
}

func TestSystemAccountStoreReportsUnreadableFiles(t *testing.T) {
	store := newSystemAccountStore(systemAccountFiles{
		passwd: filepath.Join(t.TempDir(), "missing-passwd"),
		shadow: filepath.Join(t.TempDir(), "missing-shadow"),
		group:  filepath.Join(t.TempDir(), "missing-group"),
	})
	if err := store.readable(); err == nil {
		t.Fatal("missing account files were readable")
	}
	if _, _, err := store.account("root", systemLoginPolicy{rootLogin: true}); err == nil {
		t.Fatal("account lookup without files succeeded")
	}
}

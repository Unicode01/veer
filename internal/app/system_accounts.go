package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Unicode01/veer/internal/unixcrypt"
)

// System account login reads the host's account files directly: the release
// binary is static (no libpam), and the daemon runs as root. So only local
// accounts in /etc/passwd and /etc/shadow can log in; LDAP, SSSD and other
// NSS sources are not consulted, and PAM policy (pam_faillock, pam_access,
// two-factor modules, ...) does not apply. The checks below mirror what
// pam_unix does with the shadow fields.

type systemAccountFiles struct {
	passwd string
	shadow string
	group  string
}

var defaultSystemAccountFiles = systemAccountFiles{
	passwd: "/etc/passwd",
	shadow: "/etc/shadow",
	group:  "/etc/group",
}

const (
	systemAccountFileMaxBytes  = 16 << 20
	systemAccountFileReloadGap = 30 * time.Second
	systemAccountNameMaxBytes  = 256
)

// Reasons a system account cannot log in. They go to the log, never to the
// client, which always gets the same "invalid credentials" answer.
const (
	systemLoginInvalidUser     = "invalid_user"
	systemLoginUnknownUser     = "unknown_user"
	systemLoginRootDisabled    = "root_disabled"
	systemLoginNotAdmin        = "not_admin"
	systemLoginLocked          = "locked"
	systemLoginNoPassword      = "no_password"
	systemLoginAccountExpired  = "account_expired"
	systemLoginAccountInactive = "account_inactive"
	systemLoginPasswordExpired = "password_expired"
	systemLoginUnsupportedHash = "unsupported_hash"
	systemLoginBadPassword     = "bad_password"
	systemLoginEmptyPassword   = "empty_password"
)

type systemPasswdEntry struct {
	uid uint64
	gid uint64
}

type systemShadowEntry struct {
	hash string
	// Days since 1970-01-01; -1 when the field is empty.
	lastChange int64
	maxDays    int64
	inactive   int64
	expire     int64
}

type systemGroupEntry struct {
	name    string
	gid     uint64
	members []string
}

type systemAccountSnapshot struct {
	passwd map[string]systemPasswdEntry
	shadow map[string]systemShadowEntry
	groups []systemGroupEntry
}

type systemAccountFileState struct {
	modTime int64 // UnixNano
	size    int64
}

// systemAccountStore keeps the parsed account files and reads them again
// when one changes on disk, or at the latest every 30 seconds.
type systemAccountStore struct {
	files systemAccountFiles
	now   func() time.Time

	mu       sync.Mutex
	snapshot *systemAccountSnapshot
	states   [3]systemAccountFileState
	loadedAt time.Time
}

func newSystemAccountStore(files systemAccountFiles) *systemAccountStore {
	return &systemAccountStore{files: files, now: time.Now}
}

// systemAccount is what a login decision needs about one account.
type systemAccount struct {
	name   string
	uid    uint64
	hash   string
	shadow systemShadowEntry
	admin  bool // member of a configured administrator group
}

type systemLoginPolicy struct {
	adminGroups []string
	rootLogin   bool
}

func (s *systemAccountStore) load() (*systemAccountSnapshot, error) {
	paths := [3]string{s.files.passwd, s.files.shadow, s.files.group}
	var states [3]systemAccountFileState
	for i, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		states[i] = systemAccountFileState{modTime: info.ModTime().UnixNano(), size: info.Size()}
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot != nil && states == s.states && now.Sub(s.loadedAt) < systemAccountFileReloadGap && now.Sub(s.loadedAt) >= 0 {
		return s.snapshot, nil
	}
	snapshot, err := readSystemAccountSnapshot(s.files)
	if err != nil {
		return nil, err
	}
	s.snapshot, s.states, s.loadedAt = snapshot, states, now
	return snapshot, nil
}

// invalidate makes the next lookup read the files again.
func (s *systemAccountStore) invalidate() {
	s.mu.Lock()
	s.snapshot = nil
	s.mu.Unlock()
}

// readable reports why the account files cannot be used, or nil.
func (s *systemAccountStore) readable() error {
	_, err := s.load()
	return err
}

func readSystemAccountSnapshot(files systemAccountFiles) (*systemAccountSnapshot, error) {
	snapshot := &systemAccountSnapshot{
		passwd: make(map[string]systemPasswdEntry),
		shadow: make(map[string]systemShadowEntry),
	}
	if err := readSystemAccountFile(files.passwd, func(fields []string) {
		if len(fields) < 7 {
			return
		}
		uid, err1 := strconv.ParseUint(fields[2], 10, 32)
		gid, err2 := strconv.ParseUint(fields[3], 10, 32)
		if err1 != nil || err2 != nil {
			return
		}
		if _, seen := snapshot.passwd[fields[0]]; !seen {
			snapshot.passwd[fields[0]] = systemPasswdEntry{uid: uid, gid: gid}
		}
	}); err != nil {
		return nil, err
	}
	if err := readSystemAccountFile(files.shadow, func(fields []string) {
		if len(fields) < 8 {
			return
		}
		if _, seen := snapshot.shadow[fields[0]]; seen {
			return
		}
		snapshot.shadow[fields[0]] = systemShadowEntry{
			hash:       fields[1],
			lastChange: parseShadowDays(fields[2]),
			maxDays:    parseShadowDays(fields[4]),
			inactive:   parseShadowDays(fields[6]),
			expire:     parseShadowDays(fields[7]),
		}
	}); err != nil {
		return nil, err
	}
	if err := readSystemAccountFile(files.group, func(fields []string) {
		if len(fields) < 4 {
			return
		}
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return
		}
		var members []string
		for _, member := range strings.Split(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				members = append(members, member)
			}
		}
		snapshot.groups = append(snapshot.groups, systemGroupEntry{name: fields[0], gid: gid, members: members})
	}); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// readSystemAccountFile calls line for each colon-separated entry. NIS
// compat entries (+name, -name) are skipped.
func readSystemAccountFile(path string, line func(fields []string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, systemAccountFileMaxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > systemAccountFileMaxBytes {
		return fmt.Errorf("%s is larger than %d bytes", path, systemAccountFileMaxBytes)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), systemAccountFileMaxBytes)
	for scanner.Scan() {
		text := strings.TrimRight(scanner.Text(), "\r")
		if text == "" || text[0] == '#' || text[0] == '+' || text[0] == '-' {
			continue
		}
		fields := strings.Split(text, ":")
		if fields[0] == "" {
			continue
		}
		line(fields)
	}
	return scanner.Err()
}

func parseShadowDays(field string) int64 {
	field = strings.TrimSpace(field)
	if field == "" {
		return -1
	}
	value, err := strconv.ParseInt(field, 10, 64)
	if err != nil || value < 0 {
		return -1
	}
	return value
}

// validSystemAccountName rejects names that could not be an entry in the
// account files, before they are looked up or logged.
func validSystemAccountName(name string) bool {
	if name == "" || len(name) > systemAccountNameMaxBytes {
		return false
	}
	for _, r := range name {
		if r == ':' || r == ',' || r == '/' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return name[0] != '+' && name[0] != '-'
}

// account looks name up and decides whether it may log in under policy.
// reason is "" when it may.
func (s *systemAccountStore) account(name string, policy systemLoginPolicy) (*systemAccount, string, error) {
	if !validSystemAccountName(name) {
		return nil, systemLoginInvalidUser, nil
	}
	snapshot, err := s.load()
	if err != nil {
		return nil, "", err
	}
	pw, ok := snapshot.passwd[name]
	if !ok {
		return nil, systemLoginUnknownUser, nil
	}
	sh, ok := snapshot.shadow[name]
	if !ok {
		// Hashes kept in /etc/passwd itself predate shadow files and are
		// not supported.
		return nil, systemLoginUnknownUser, nil
	}
	account := &systemAccount{name: name, uid: pw.uid, hash: sh.hash, shadow: sh}
	for _, group := range snapshot.groups {
		if !containsString(policy.adminGroups, group.name) {
			continue
		}
		if group.gid == pw.gid || containsString(group.members, name) {
			account.admin = true
			break
		}
	}
	if account.uid == 0 {
		if !policy.rootLogin {
			return account, systemLoginRootDisabled, nil
		}
	} else if !account.admin {
		return account, systemLoginNotAdmin, nil
	}
	if reason := systemShadowRefusal(sh, s.now()); reason != "" {
		return account, reason, nil
	}
	return account, "", nil
}

// systemShadowRefusal applies the shadow fields the way pam_unix does.
func systemShadowRefusal(entry systemShadowEntry, now time.Time) string {
	switch {
	case entry.hash == "":
		return systemLoginNoPassword
	case strings.HasPrefix(entry.hash, "!") || strings.HasPrefix(entry.hash, "*"):
		return systemLoginLocked
	case unixcrypt.Scheme(entry.hash) == "":
		return systemLoginUnsupportedHash
	}
	today := now.Unix() / 86400
	if entry.expire >= 0 && today >= entry.expire {
		return systemLoginAccountExpired
	}
	if entry.lastChange == 0 {
		// passwd -e: the password must be changed before the next login.
		return systemLoginPasswordExpired
	}
	if entry.lastChange > 0 && entry.maxDays >= 0 && today-entry.lastChange > entry.maxDays {
		if entry.inactive >= 0 && today-entry.lastChange > entry.maxDays+entry.inactive {
			return systemLoginAccountInactive
		}
		return systemLoginPasswordExpired
	}
	return ""
}

// verifySystemPassword checks password against the account's hash.
func verifySystemPassword(account *systemAccount, password string) string {
	if password == "" {
		return systemLoginEmptyPassword
	}
	switch err := unixcrypt.Verify(account.hash, password); {
	case err == nil:
		return ""
	case errors.Is(err, unixcrypt.ErrMismatch):
		return systemLoginBadPassword
	default:
		return systemLoginUnsupportedHash
	}
}

// systemLoginDecoyHash costs about what a default yescrypt hash costs, so an
// unknown or refused account takes as long to answer as a wrong password.
const systemLoginDecoyHash = "$y$j9T$LdJMENpBABJJ3hIHjB1Bi.$iofk68xbXBoXKsxTyMBCh2qkQuzQZ2Zik521F9TsTq6"

func spendSystemLoginDecoyHash(password string) {
	_ = unixcrypt.Verify(systemLoginDecoyHash, password+"\x00")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

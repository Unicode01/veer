// Package unixcrypt verifies passwords against the crypt(3) hashes found in
// /etc/shadow, in pure Go so that the static release binary needs no libcrypt.
//
// Supported: yescrypt ($y$, the default of Debian 11+, Ubuntu 22.04+ and
// Fedora 35+), sha512-crypt ($6$), sha256-crypt ($5$), md5-crypt ($1$) and
// bcrypt ($2a$, $2b$, $2y$). Everything else, including traditional DES crypt,
// is reported as unsupported rather than guessed at.
package unixcrypt

import (
	"crypto/subtle"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrMismatch means the password does not match the hash.
	ErrMismatch = errors.New("password does not match")
	// ErrUnsupported means the hash uses a scheme or parameters this
	// package does not implement or refuses to run (for example a cost
	// beyond the limits below).
	ErrUnsupported = errors.New("unsupported password hash")
	// ErrMalformed means the hash string cannot be parsed.
	ErrMalformed = errors.New("malformed password hash")
)

// Limits keep a hash whose parameters were raised far beyond any
// distribution default from tying up the daemon. /etc/shadow is written by
// root, so these are guards against mistakes, not against an attacker.
const (
	maxSHACryptRounds    = 10_000_000
	maxYescryptMemory    = 1 << 30 // bytes of V
	maxYescryptTimeParam = 16
	maxPasswordBytes     = 4096
)

// Scheme names the hashing scheme of hash ("yescrypt", "sha512crypt", ...),
// or "" when it is not one this package knows.
func Scheme(hash string) string {
	switch {
	case strings.HasPrefix(hash, "$y$"):
		return "yescrypt"
	case strings.HasPrefix(hash, "$6$"):
		return "sha512crypt"
	case strings.HasPrefix(hash, "$5$"):
		return "sha256crypt"
	case strings.HasPrefix(hash, "$1$"):
		return "md5crypt"
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return "bcrypt"
	}
	return ""
}

// Verify reports whether password matches hash: nil on a match, ErrMismatch
// when it does not, and ErrUnsupported or ErrMalformed when hash cannot be
// checked at all.
func Verify(hash, password string) error {
	if len(password) > maxPasswordBytes {
		return ErrMismatch
	}
	var computed string
	var err error
	switch Scheme(hash) {
	case "yescrypt":
		computed, err = yescryptCrypt([]byte(password), hash)
	case "sha512crypt":
		computed, err = shaCrypt(sha512Variant, []byte(password), hash)
	case "sha256crypt":
		computed, err = shaCrypt(sha256Variant, []byte(password), hash)
	case "md5crypt":
		computed, err = md5Crypt([]byte(password), hash)
	case "bcrypt":
		switch err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); {
		case err == nil:
			return nil
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return ErrMismatch
		case errors.Is(err, bcrypt.ErrHashTooShort):
			return ErrMalformed
		default:
			var cost bcrypt.InvalidCostError
			if errors.As(err, &cost) {
				return ErrUnsupported
			}
			return ErrMalformed
		}
	default:
		return ErrUnsupported
	}
	if err != nil {
		return err
	}
	if len(computed) != len(hash) || subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) != 1 {
		return ErrMismatch
	}
	return nil
}

// itoa64 is the crypt(3) base-64 alphabet.
const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func atoi64(c byte) uint32 {
	switch {
	case c == '.':
		return 0
	case c == '/':
		return 1
	case c >= '0' && c <= '9':
		return uint32(c-'0') + 2
	case c >= 'A' && c <= 'Z':
		return uint32(c-'A') + 12
	case c >= 'a' && c <= 'z':
		return uint32(c-'a') + 38
	}
	return 64
}

// appendB64From24 appends n characters of the 24-bit value made of b2, b1,
// b0, least significant six bits first, as md5-crypt and sha-crypt do.
func appendB64From24(dst []byte, b2, b1, b0 byte, n int) []byte {
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	for ; n > 0; n-- {
		dst = append(dst, itoa64[w&0x3f])
		w >>= 6
	}
	return dst
}

package unixcrypt

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

type cryptVector struct {
	password string
	hash     string
}

// Vectors produced by libxcrypt (crypt(3) on Debian 12) and OpenSSL 3
// (`openssl passwd -1/-5/-6`); the sha-crypt ones include the examples of
// Drepper's specification.
var knownVectors = []cryptVector{
	{"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
	{"Hello world!", "$6$saltstringsaltst$e.3mR68CqZEpesEX1HlFZT6sEanSOjM/b5UoDyDo00a8syek2cJldMjrbtKP86.FJvzluVR7nc3DNzelAwTxj."},
	{"Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"},
	{"Hello world!", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
	{"Hello world!", "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1"},
	{"abc", "$1$$j0yT3c/2mYPQF09fpvPLb0"},
}

func TestVerifyKnownVectors(t *testing.T) {
	vectors := append(append([]cryptVector{}, knownVectors...), yescryptVectors...)
	for _, v := range vectors {
		if err := Verify(v.hash, v.password); err != nil {
			t.Errorf("Verify(%q, %q) = %v, want match", v.hash, v.password, err)
		}
		if err := Verify(v.hash, v.password+"x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("Verify(%q, wrong password) = %v, want ErrMismatch", v.hash, err)
		}
	}
}

func TestVerifyBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("router-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		h := prefix + string(hash[4:])
		if got := Scheme(h); got != "bcrypt" {
			t.Fatalf("Scheme(%q) = %q", h, got)
		}
		if err := Verify(h, "router-secret"); err != nil {
			t.Errorf("Verify(%s...) = %v", prefix, err)
		}
		if err := Verify(h, "router-secreT"); !errors.Is(err, ErrMismatch) {
			t.Errorf("Verify(%s..., wrong) = %v, want ErrMismatch", prefix, err)
		}
	}
	// A published $2b$ vector (OpenBSD regress).
	if err := Verify("$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U"); err != nil {
		t.Errorf("OpenBSD $2b$ vector: %v", err)
	}
}

func TestVerifyRejectsUnsupportedAndMalformed(t *testing.T) {
	for _, hash := range []string{
		"",
		"x",
		"*",
		"!",
		"!$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
		"abJnggxhB/yWI", // traditional DES
		"$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D",
		"$gy$j9T$salt$hash",
		"$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq",
	} {
		if err := Verify(hash, "password"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Verify(%q) = %v, want ErrUnsupported", hash, err)
		}
	}
	for _, hash := range []string{
		"$y$",
		"$y$j9T",
		"$y$j9T$",
		"$y$j9T$!!$abc",
		"$y$~9T$salt$hash",
		"$5$rounds=abc$salt$hash",
		"$2b$05$tooshort",
	} {
		err := Verify(hash, "password")
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrMismatch) {
			t.Errorf("Verify(%q) = %v, want ErrMalformed or ErrMismatch", hash, err)
		}
		if err == nil {
			t.Errorf("Verify(%q) matched", hash)
		}
	}
	// Parameters beyond the limits are refused instead of computed.
	for _, hash := range []string{
		"$6$rounds=999999999$saltstring$abc",
		"$y$jMT$LdJMENpBABJJ3hIHjB1Bi.$abc", // N = 2^25, r = 32: 128 GiB
	} {
		if err := Verify(hash, "password"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Verify(%q) = %v, want ErrUnsupported", hash, err)
		}
	}
}

func TestVerifyTreatsOverlongPasswordAsMismatch(t *testing.T) {
	long := string(bytes.Repeat([]byte("a"), maxPasswordBytes+1))
	if err := Verify(knownVectors[0].hash, long); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify(overlong) = %v, want ErrMismatch", err)
	}
}

// Classic scrypt is yescrypt with no flags, so the salsa20/8 BlockMix, SMix
// and PBKDF2 plumbing can be checked against x/crypto's independent scrypt.
func TestYescryptClassicModeMatchesScrypt(t *testing.T) {
	for _, tc := range []struct {
		password, salt string
		n              uint64
		r, p           uint32
	}{
		{"", "", 16, 1, 1},
		{"password", "NaCl", 1024, 8, 16},
		{"pleaseletmein", "SodiumChloride", 16384, 8, 1},
		{"veer", "salt", 64, 3, 2},
	} {
		want, err := scrypt.Key([]byte(tc.password), []byte(tc.salt), int(tc.n), int(tc.r), int(tc.p), 64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := yescryptKDF([]byte(tc.password), []byte(tc.salt), yescryptParams{n: tc.n, r: tc.r, p: tc.p}, 64)
		if err != nil {
			t.Fatalf("yescryptKDF(%+v): %v", tc, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("classic yescrypt(%q, %q, N=%d r=%d p=%d) = %x, want scrypt %x", tc.password, tc.salt, tc.n, tc.r, tc.p, got, want)
		}
	}
}

func TestYescryptSettingEncoding(t *testing.T) {
	params, rest, err := decodeYescryptSetting("$y$j9T$saltpart$hashpart")
	if err != nil {
		t.Fatal(err)
	}
	if params.flags != yescryptRWDefaults || params.n != 4096 || params.r != 32 || params.p != 1 || params.t != 0 {
		t.Fatalf("j9T decoded to %+v", params)
	}
	if rest != "saltpart$hashpart" {
		t.Fatalf("rest = %q", rest)
	}
	// "jD5.7": N = 2^14? No: D is 15, so N_log2 = 16; r = 8 ('5' = 7, +1);
	// have = 1 ('.' = 0, +1) so p follows: '7' = 9, +2 = 11.
	params, _, err = decodeYescryptSetting("$y$jD5.7$x")
	if err != nil {
		t.Fatal(err)
	}
	if params.n != 1<<16 || params.r != 8 || params.p != 11 {
		t.Fatalf("jD5.7 decoded to %+v", params)
	}
	salt, err := decode64Bytes("LdJMENpBABJJ3hIHjB1Bi.", 64)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(encode64Bytes(nil, salt)); got != "LdJMENpBABJJ3hIHjB1Bi." {
		t.Fatalf("salt round trip = %q", got)
	}
}

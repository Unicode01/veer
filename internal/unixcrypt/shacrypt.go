package unixcrypt

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strconv"
	"strings"
)

// sha-crypt as specified by Ulrich Drepper ("Unix crypt using SHA-256 and
// SHA-512", the scheme glibc and libxcrypt implement as $5$ and $6$).

const (
	shaCryptDefaultRounds = 5000
	shaCryptMinRounds     = 1000
	shaCryptMaxRounds     = 999_999_999
	shaCryptMaxSalt       = 16
)

type shaCryptVariant struct {
	prefix string
	newSum func() hash.Hash
	size   int
	// groups lists the digest bytes of each 4-character output group as
	// (b2, b1, b0); tail encodes what is left.
	groups [][3]int
	tail   func(dst, sum []byte) []byte
}

var sha512Variant = &shaCryptVariant{
	prefix: "$6$",
	newSum: sha512.New,
	size:   sha512.Size,
	groups: [][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
		{28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13},
		{56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41},
	},
	tail: func(dst, sum []byte) []byte {
		return appendB64From24(dst, 0, 0, sum[63], 2)
	},
}

var sha256Variant = &shaCryptVariant{
	prefix: "$5$",
	newSum: sha256.New,
	size:   sha256.Size,
	groups: [][3]int{
		{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
		{15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29},
	},
	tail: func(dst, sum []byte) []byte {
		return appendB64From24(dst, 0, sum[31], sum[30], 3)
	},
}

// shaCrypt computes the full $5$/$6$ string for password under the setting
// (prefix, optional rounds=N$, salt) taken from setting.
func shaCrypt(v *shaCryptVariant, password []byte, setting string) (string, error) {
	rest := setting[len(v.prefix):]
	rounds := shaCryptDefaultRounds
	customRounds := false
	if strings.HasPrefix(rest, "rounds=") {
		digits := rest[len("rounds="):]
		if end := strings.IndexByte(digits, '$'); end > 0 {
			value, err := strconv.ParseUint(digits[:end], 10, 64)
			if err != nil {
				return "", ErrMalformed
			}
			switch {
			case value < shaCryptMinRounds:
				rounds = shaCryptMinRounds
			case value > shaCryptMaxRounds:
				rounds = shaCryptMaxRounds
			default:
				rounds = int(value)
			}
			customRounds = true
			rest = digits[end+1:]
		}
	}
	if rounds > maxSHACryptRounds {
		return "", ErrUnsupported
	}
	saltLen := strings.IndexByte(rest, '$')
	if saltLen < 0 {
		saltLen = len(rest)
	}
	if saltLen > shaCryptMaxSalt {
		saltLen = shaCryptMaxSalt
	}
	salt := []byte(rest[:saltLen])

	h := v.newSum()
	h.Write(password)
	h.Write(salt)
	h.Write(password)
	alternate := h.Sum(nil)

	h.Reset()
	h.Write(password)
	h.Write(salt)
	n := len(password)
	for ; n > v.size; n -= v.size {
		h.Write(alternate)
	}
	h.Write(alternate[:n])
	for n = len(password); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write(alternate)
		} else {
			h.Write(password)
		}
	}
	sum := h.Sum(nil)

	h.Reset()
	for i := 0; i < len(password); i++ {
		h.Write(password)
	}
	p := repeatDigest(h.Sum(nil), len(password))

	h.Reset()
	for i := 0; i < 16+int(sum[0]); i++ {
		h.Write(salt)
	}
	s := repeatDigest(h.Sum(nil), len(salt))

	for i := 0; i < rounds; i++ {
		h.Reset()
		if i&1 != 0 {
			h.Write(p)
		} else {
			h.Write(sum)
		}
		if i%3 != 0 {
			h.Write(s)
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 != 0 {
			h.Write(sum)
		} else {
			h.Write(p)
		}
		sum = h.Sum(sum[:0])
	}

	out := make([]byte, 0, len(setting)+90)
	out = append(out, v.prefix...)
	if customRounds {
		out = append(out, "rounds="...)
		out = strconv.AppendInt(out, int64(rounds), 10)
		out = append(out, '$')
	}
	out = append(out, salt...)
	out = append(out, '$')
	for _, g := range v.groups {
		out = appendB64From24(out, sum[g[0]], sum[g[1]], sum[g[2]], 4)
	}
	out = v.tail(out, sum)
	return string(out), nil
}

func repeatDigest(digest []byte, length int) []byte {
	out := make([]byte, length)
	for i := 0; i < length; i += len(digest) {
		copy(out[i:], digest)
	}
	return out
}

// md5Crypt computes the $1$ string of Poul-Henning Kamp's md5-crypt.
func md5Crypt(password []byte, setting string) (string, error) {
	const prefix = "$1$"
	rest := setting[len(prefix):]
	saltLen := strings.IndexByte(rest, '$')
	if saltLen < 0 {
		saltLen = len(rest)
	}
	if saltLen > 8 {
		saltLen = 8
	}
	salt := []byte(rest[:saltLen])

	alt := md5.New()
	alt.Write(password)
	alt.Write(salt)
	alt.Write(password)
	alternate := alt.Sum(nil)

	h := md5.New()
	h.Write(password)
	h.Write([]byte(prefix))
	h.Write(salt)
	for n := len(password); n > 0; n -= md5.Size {
		if n > md5.Size {
			h.Write(alternate)
		} else {
			h.Write(alternate[:n])
		}
	}
	for n := len(password); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write([]byte{0})
		} else {
			h.Write(password[:1])
		}
	}
	sum := h.Sum(nil)

	for i := 0; i < 1000; i++ {
		h.Reset()
		if i&1 != 0 {
			h.Write(password)
		} else {
			h.Write(sum)
		}
		if i%3 != 0 {
			h.Write(salt)
		}
		if i%7 != 0 {
			h.Write(password)
		}
		if i&1 != 0 {
			h.Write(sum)
		} else {
			h.Write(password)
		}
		sum = h.Sum(sum[:0])
	}

	out := make([]byte, 0, len(prefix)+len(salt)+23)
	out = append(out, prefix...)
	out = append(out, salt...)
	out = append(out, '$')
	out = appendB64From24(out, sum[0], sum[6], sum[12], 4)
	out = appendB64From24(out, sum[1], sum[7], sum[13], 4)
	out = appendB64From24(out, sum[2], sum[8], sum[14], 4)
	out = appendB64From24(out, sum[3], sum[9], sum[15], 4)
	out = appendB64From24(out, sum[4], sum[10], sum[5], 4)
	out = appendB64From24(out, 0, 0, sum[11], 2)
	return string(out), nil
}

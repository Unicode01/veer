package unixcrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"strings"
)

// yescrypt, ported from the reference implementation (yescrypt-ref.c of
// yescrypt 1.1, the code libxcrypt ships as $y$). The port keeps the
// reference's data layout on purpose: blocks are held as 32-bit words in the
// "SIMD shuffled" order (word i of a 64-byte block holds input word i*5%16),
// and pwxform and Integerify read that shuffled layout, so following it word
// for word is what makes the results match libxcrypt.
//
// Supported: the $y$ encoding with the flavors yescrypt ships (classic
// scrypt, WORM and the RW defaults every distribution uses), p and t. Not
// supported: a shared ROM (NROM) and hash upgrades (g), which crypt(3)
// hashes do not use, and the $7$ encoding.

const (
	yescryptWORM    = 0x001
	yescryptRW      = 0x002
	yescryptPrehash = 0x10000000

	yescryptRWFlavorMask = 0x3fc
	// The only RW flavor the reference implements: ROUNDS_6, GATHER_4,
	// SIMPLE_2 and SBOX_12K.
	yescryptRWDefaults = yescryptRW | 0x004 | 0x010 | 0x020 | 0x080

	pwxSimple = 2
	pwxGather = 4
	pwxRounds = 6
	sWidth    = 8

	pwxWords  = pwxGather * pwxSimple * 2         // 16 uint32 = 64 bytes
	sBytes    = 3 * (1 << sWidth) * pwxSimple * 8 // 12288
	sWords    = sBytes / 4
	sMask     = ((1 << sWidth) - 1) * pwxSimple * 8 // byte mask, 4080
	sSubWords = (1 << sWidth) * pwxSimple * 2       // words in each of S0, S1, S2
)

type yescryptParams struct {
	flags uint32
	n     uint64
	r     uint32
	p     uint32
	t     uint32
}

// yescryptCrypt computes the full $y$ string for password with the
// parameters and salt of setting.
func yescryptCrypt(password []byte, setting string) (string, error) {
	params, rest, err := decodeYescryptSetting(setting)
	if err != nil {
		return "", err
	}
	saltText := rest
	if end := strings.LastIndexByte(rest, '$'); end >= 0 {
		saltText = rest[:end]
	}
	salt, err := decode64Bytes(saltText, 64)
	if err != nil {
		return "", err
	}
	prefix := setting[:len(setting)-len(rest)]
	sum, err := yescryptKDF(password, salt, params, 32)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, len(prefix)+len(saltText)+1+43)
	out = append(out, prefix...)
	out = append(out, saltText...)
	out = append(out, '$')
	out = encode64Bytes(out, sum)
	return string(out), nil
}

// decodeYescryptSetting parses "$y$<flavor><N><r>[<have>...]$" and returns
// the parameters and what follows the closing '$'.
func decodeYescryptSetting(setting string) (yescryptParams, string, error) {
	params := yescryptParams{p: 1}
	if !strings.HasPrefix(setting, "$y$") {
		return params, "", ErrMalformed
	}
	src := setting[3:]
	flavor, src, err := decode64Uint32(src, 0)
	if err != nil {
		return params, "", err
	}
	switch {
	case flavor < yescryptRW:
		params.flags = flavor
	case flavor <= yescryptRW+(yescryptRWFlavorMask>>2):
		params.flags = yescryptRW + ((flavor - yescryptRW) << 2)
	default:
		return params, "", ErrMalformed
	}
	nLog2, src, err := decode64Uint32(src, 1)
	if err != nil {
		return params, "", err
	}
	if nLog2 > 63 {
		return params, "", ErrMalformed
	}
	params.n = uint64(1) << nLog2
	if params.r, src, err = decode64Uint32(src, 1); err != nil {
		return params, "", err
	}
	if src != "" && src[0] != '$' {
		var have uint32
		if have, src, err = decode64Uint32(src, 1); err != nil {
			return params, "", err
		}
		if have&1 != 0 {
			if params.p, src, err = decode64Uint32(src, 2); err != nil {
				return params, "", err
			}
		}
		if have&2 != 0 {
			if params.t, src, err = decode64Uint32(src, 1); err != nil {
				return params, "", err
			}
		}
		if have&4 != 0 {
			// g: hash upgrades, which yescrypt itself rejects.
			return params, "", ErrUnsupported
		}
		if have&8 != 0 {
			// NROM: a shared ROM, never part of a crypt(3) hash.
			return params, "", ErrUnsupported
		}
		if have&^0xf != 0 {
			return params, "", ErrMalformed
		}
	}
	if src == "" || src[0] != '$' {
		return params, "", ErrMalformed
	}
	return params, src[1:], nil
}

// decode64Uint32 reads one variable-length integer of the yescrypt setting.
func decode64Uint32(src string, min uint32) (uint32, string, error) {
	if src == "" {
		return 0, "", ErrMalformed
	}
	c := atoi64(src[0])
	src = src[1:]
	if c > 63 {
		return 0, "", ErrMalformed
	}
	value := uint64(min)
	start, end, chars, shift := uint32(0), uint32(47), 1, uint32(0)
	for c > end {
		value += uint64(end+1-start) << shift
		start = end + 1
		end = start + (62-end)/2
		chars++
		shift += 6
	}
	value += uint64(c-start) << shift
	for ; chars > 1; chars-- {
		if src == "" {
			return 0, "", ErrMalformed
		}
		c = atoi64(src[0])
		src = src[1:]
		if c > 63 {
			return 0, "", ErrMalformed
		}
		shift -= 6
		value += uint64(c) << shift
	}
	if value > 0xffffffff {
		return 0, "", ErrMalformed
	}
	return uint32(value), src, nil
}

// decode64Bytes decodes yescrypt's little-endian base-64: each group of up
// to four characters carries up to three bytes, low bits first.
func decode64Bytes(src string, maxLen int) ([]byte, error) {
	out := make([]byte, 0, len(src)*3/4)
	for len(src) > 0 {
		var value, have uint32
		n := 0
		for n < 4 && n < len(src) {
			c := atoi64(src[n])
			if c > 63 {
				return nil, ErrMalformed
			}
			value |= c << have
			have += 6
			n++
		}
		src = src[n:]
		if have < 12 {
			return nil, ErrMalformed
		}
		for have >= 8 {
			out = append(out, byte(value))
			value >>= 8
			have -= 8
		}
		if value != 0 {
			return nil, ErrMalformed
		}
		if len(out) > maxLen {
			return nil, ErrMalformed
		}
	}
	return out, nil
}

func encode64Bytes(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		var value, have uint32
		for have < 24 && i < len(src) {
			value |= uint32(src[i]) << have
			have += 8
			i++
		}
		for n := uint32(0); n < have; n += 6 {
			dst = append(dst, itoa64[value&0x3f])
			value >>= 6
		}
	}
	return dst
}

func yescryptKDF(password, salt []byte, params yescryptParams, dkLen int) ([]byte, error) {
	flags, n, r, p, t := params.flags, params.n, params.r, params.p, params.t
	var prehashed [32]byte
	if flags&yescryptRW != 0 && p >= 1 && n/uint64(p) >= 0x100 && n/uint64(p)*uint64(r) >= 0x20000 {
		dk, err := yescryptKDFBody(password, salt, flags|yescryptPrehash, n>>6, r, p, 0, len(prehashed))
		if err != nil {
			return nil, err
		}
		copy(prehashed[:], dk)
		password = prehashed[:]
	}
	return yescryptKDFBody(password, salt, flags, n, r, p, t, dkLen)
}

func yescryptKDFBody(password, salt []byte, flags uint32, n uint64, r, p, t uint32, dkLen int) ([]byte, error) {
	switch flags &^ yescryptPrehash & 0x3 {
	case 0:
		if flags != 0 || t != 0 {
			return nil, ErrUnsupported
		}
	case yescryptWORM:
		if flags != yescryptWORM {
			return nil, ErrUnsupported
		}
	case yescryptRW:
		if flags&^yescryptPrehash != yescryptRWDefaults {
			return nil, ErrUnsupported
		}
	default:
		return nil, ErrUnsupported
	}
	if r < 1 || p < 1 || n <= 1 || n&(n-1) != 0 || uint64(r)*uint64(p) >= 1<<30 {
		return nil, ErrMalformed
	}
	if flags&yescryptRW != 0 && n/uint64(p) <= 3 {
		return nil, ErrMalformed
	}
	if t > maxYescryptTimeParam || n > maxYescryptMemory/128/uint64(r) {
		return nil, ErrUnsupported
	}
	if uint64(128)*uint64(r)*uint64(p) > maxYescryptMemory {
		return nil, ErrUnsupported
	}

	var passwd [32]byte
	if flags != 0 {
		key := []byte("yescrypt-prehash")
		if flags&yescryptPrehash == 0 {
			key = key[:8]
		}
		copy(passwd[:], hmacSHA256(key, password))
		password = passwd[:]
	}

	blockBytes := 128 * int(r)
	b := pbkdf2SHA256Once(password, salt, blockBytes*int(p))
	if flags != 0 {
		// The reference copies the first 32 bytes of B over the buffer the
		// password points to, so everything after this uses them.
		copy(passwd[:], b[:32])
	}

	s := 32 * int(r)
	v := make([]uint32, uint64(s)*n)
	xy := make([]uint32, 2*s)
	if flags&yescryptRW != 0 {
		sbox := make([]uint32, sWords*int(p))
		yescryptSMix(b, int(r), n, int(p), t, flags, v, xy, sbox, passwd[:])
	} else {
		for i := 0; i < int(p); i++ {
			yescryptSMix(b[i*blockBytes:(i+1)*blockBytes], int(r), n, 1, t, flags, v, xy, nil, nil)
		}
	}

	dk := pbkdf2SHA256Once(password, b, max(dkLen, 32))
	if flags != 0 && flags&yescryptPrehash == 0 {
		clientKey := hmacSHA256(dk[:32], []byte("Client Key"))
		stored := sha256.Sum256(clientKey)
		n := dkLen
		if n > len(stored) {
			n = len(stored)
		}
		copy(dk, stored[:n])
	}
	return dk[:dkLen], nil
}

func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// pbkdf2SHA256Once is PBKDF2-HMAC-SHA256 with one iteration, the only count
// yescrypt uses.
func pbkdf2SHA256Once(password, salt []byte, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	mac := hmac.New(sha256.New, password)
	var counter [4]byte
	for block := uint32(1); len(out) < length; block++ {
		mac.Reset()
		mac.Write(salt)
		binary.BigEndian.PutUint32(counter[:], block)
		mac.Write(counter[:])
		out = mac.Sum(out)
	}
	return out[:length]
}

type pwxformCtx struct {
	s          []uint32
	s0, s1, s2 int // word offsets of S0, S1, S2 in s
	w          int
}

// yescryptSMix is the reference smix(): b holds p blocks of 128*r bytes.
func yescryptSMix(b []byte, r int, n uint64, p int, t uint32, flags uint32, v, xy, sbox []uint32, passwd []byte) {
	s := 32 * r
	nChunk := n / uint64(p)
	nLoopAll := nChunk
	if flags&yescryptRW != 0 {
		if t <= 1 {
			if t != 0 {
				nLoopAll *= 2
			}
			nLoopAll = (nLoopAll + 2) / 3
		} else {
			nLoopAll *= uint64(t - 1)
		}
	} else if t != 0 {
		if t == 1 {
			nLoopAll += (nLoopAll + 1) / 2
		}
		nLoopAll *= uint64(t)
	}
	nLoopRW := uint64(0)
	if flags&yescryptRW != 0 {
		nLoopRW = nLoopAll / uint64(p)
	}
	nChunk &^= 1
	nLoopAll++
	nLoopAll &^= 1
	nLoopRW++
	nLoopRW &^= 1

	ctxs := make([]*pwxformCtx, p)
	vChunk := uint64(0)
	for i := 0; i < p; i++ {
		np := nChunk
		if i == p-1 {
			np = n - vChunk
		}
		bp := b[i*4*s : (i+1)*4*s]
		vp := v[uint64(s)*vChunk:]
		var ctx *pwxformCtx
		if flags&yescryptRW != 0 {
			ctx = &pwxformCtx{s: sbox[i*sWords : (i+1)*sWords]}
			// SMix1 of one 128-byte block with no flags fills S_i.
			yescryptSMix1(bp, 1, sBytes/128, 0, ctx.s, xy, nil)
			ctx.s2 = 0
			ctx.s1 = ctx.s2 + sSubWords
			ctx.s0 = ctx.s1 + sSubWords
			ctx.w = 0
			if i == 0 {
				copy(passwd, hmacSHA256(bp[4*s-64:4*s], passwd))
			}
		}
		ctxs[i] = ctx
		yescryptSMix1(bp, r, np, flags, vp, xy, ctx)
		yescryptSMix2(bp, r, p2floor(np), nLoopRW, flags, vp, xy, ctx)
		vChunk += nChunk
	}
	for i := 0; i < p; i++ {
		bp := b[i*4*s : (i+1)*4*s]
		yescryptSMix2(bp, r, n, nLoopAll-nLoopRW, flags&^yescryptRW, v, xy, ctxs[i])
	}
}

func loadShuffled(x []uint32, b []byte, r int) {
	for k := 0; k < 2*r; k++ {
		for i := 0; i < 16; i++ {
			x[k*16+i] = binary.LittleEndian.Uint32(b[(k*16+i*5%16)*4:])
		}
	}
}

func storeShuffled(b []byte, x []uint32, r int) {
	for k := 0; k < 2*r; k++ {
		for i := 0; i < 16; i++ {
			binary.LittleEndian.PutUint32(b[(k*16+i*5%16)*4:], x[k*16+i])
		}
	}
}

func yescryptSMix1(b []byte, r int, n uint64, flags uint32, v, xy []uint32, ctx *pwxformCtx) {
	s := 32 * r
	x := xy[:s]
	y := xy[s : 2*s]
	loadShuffled(x, b, r)
	for i := uint64(0); i < n; i++ {
		copy(v[i*uint64(s):(i+1)*uint64(s)], x)
		if flags&yescryptRW != 0 && i > 1 {
			j := wrap(integerify(x, r), i)
			blockXOR(x, v[j*uint64(s):(j+1)*uint64(s)])
		}
		if ctx != nil {
			blockMixPwxform(x, ctx, r)
		} else {
			blockMixSalsa8(x, y, r)
		}
	}
	storeShuffled(b, x, r)
}

func yescryptSMix2(b []byte, r int, n, nLoop uint64, flags uint32, v, xy []uint32, ctx *pwxformCtx) {
	if nLoop == 0 {
		return
	}
	s := 32 * r
	x := xy[:s]
	y := xy[s : 2*s]
	loadShuffled(x, b, r)
	for i := uint64(0); i < nLoop; i++ {
		j := integerify(x, r) & (n - 1)
		vj := v[j*uint64(s) : (j+1)*uint64(s)]
		blockXOR(x, vj)
		if flags&yescryptRW != 0 {
			copy(vj, x)
		}
		if ctx != nil {
			blockMixPwxform(x, ctx, r)
		} else {
			blockMixSalsa8(x, y, r)
		}
	}
	storeShuffled(b, x, r)
}

func p2floor(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	return uint64(1) << (63 - bits.LeadingZeros64(x))
}

func wrap(x, i uint64) uint64 {
	n := p2floor(i)
	return (x & (n - 1)) + (i - n)
}

// integerify reads the first 64 bits of the last 64-byte block; word 13 of
// the shuffled block is input word 1.
func integerify(x []uint32, r int) uint64 {
	last := x[(2*r-1)*16:]
	return uint64(last[13])<<32 | uint64(last[0])
}

func blockXOR(dst, src []uint32) {
	src = src[:len(dst)]
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func blockMixSalsa8(b, y []uint32, r int) {
	var x [16]uint32
	copy(x[:], b[(2*r-1)*16:])
	for i := 0; i < 2*r; i++ {
		blockXOR(x[:], b[i*16:(i+1)*16])
		salsa20Shuffled(&x, 8)
		copy(y[i*16:], x[:])
	}
	for i := 0; i < r; i++ {
		copy(b[i*16:(i+1)*16], y[(i*2)*16:])
	}
	for i := 0; i < r; i++ {
		copy(b[(i+r)*16:(i+r+1)*16], y[(i*2+1)*16:])
	}
}

func blockMixPwxform(b []uint32, ctx *pwxformCtx, r int) {
	var x [pwxWords]uint32
	r1 := 128 * r / (pwxWords * 4)
	copy(x[:], b[(r1-1)*pwxWords:])
	for i := 0; i < r1; i++ {
		if r1 > 1 {
			blockXOR(x[:], b[i*pwxWords:(i+1)*pwxWords])
		}
		ctx.pwxform(&x)
		copy(b[i*pwxWords:], x[:])
	}
	i := (r1 - 1) * pwxWords * 4 / 64
	var block [16]uint32
	copy(block[:], b[i*16:])
	salsa20Shuffled(&block, 2)
	copy(b[i*16:], block[:])
	// With 64-byte pwxform blocks r1 = 2r, so the reference's remaining
	// "B_i <-- H(B_i xor B_{i-1})" loop never runs.
}

func (c *pwxformCtx) pwxform(b *[pwxWords]uint32) {
	s0 := c.s[c.s0 : c.s0+sSubWords]
	s1 := c.s[c.s1 : c.s1+sSubWords]
	s2 := c.s[c.s2 : c.s2+sSubWords]
	w := c.w
	for i := 0; i < pwxRounds; i++ {
		for j := 0; j < pwxGather; j++ {
			base := j * pwxSimple * 2
			p0 := int(b[base]&sMask) / 4
			p1 := int(b[base+1]&sMask) / 4
			for k := 0; k < pwxSimple; k++ {
				lo := base + 2*k
				v0 := uint64(s0[p0+2*k+1])<<32 | uint64(s0[p0+2*k])
				v1 := uint64(s1[p1+2*k+1])<<32 | uint64(s1[p1+2*k])
				value := uint64(b[lo+1]) * uint64(b[lo])
				value += v0
				value ^= v1
				b[lo] = uint32(value)
				b[lo+1] = uint32(value >> 32)
				if i != 0 && i != pwxRounds-1 {
					s2[2*w] = uint32(value)
					s2[2*w+1] = uint32(value >> 32)
					w++
				}
			}
		}
	}
	c.s0, c.s1, c.s2 = c.s2, c.s0, c.s1
	c.w = w & ((1<<sWidth)*pwxSimple - 1)
}

// salsa20Shuffled is the reference's salsa20(): b is in shuffled order and
// gets the feed-forward sum of rounds of Salsa20 added to it.
func salsa20Shuffled(b *[16]uint32, rounds int) {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i*5%16] = b[i]
	}
	for i := 0; i < rounds; i += 2 {
		x[4] ^= bits.RotateLeft32(x[0]+x[12], 7)
		x[8] ^= bits.RotateLeft32(x[4]+x[0], 9)
		x[12] ^= bits.RotateLeft32(x[8]+x[4], 13)
		x[0] ^= bits.RotateLeft32(x[12]+x[8], 18)

		x[9] ^= bits.RotateLeft32(x[5]+x[1], 7)
		x[13] ^= bits.RotateLeft32(x[9]+x[5], 9)
		x[1] ^= bits.RotateLeft32(x[13]+x[9], 13)
		x[5] ^= bits.RotateLeft32(x[1]+x[13], 18)

		x[14] ^= bits.RotateLeft32(x[10]+x[6], 7)
		x[2] ^= bits.RotateLeft32(x[14]+x[10], 9)
		x[6] ^= bits.RotateLeft32(x[2]+x[14], 13)
		x[10] ^= bits.RotateLeft32(x[6]+x[2], 18)

		x[3] ^= bits.RotateLeft32(x[15]+x[11], 7)
		x[7] ^= bits.RotateLeft32(x[3]+x[15], 9)
		x[11] ^= bits.RotateLeft32(x[7]+x[3], 13)
		x[15] ^= bits.RotateLeft32(x[11]+x[7], 18)

		x[1] ^= bits.RotateLeft32(x[0]+x[3], 7)
		x[2] ^= bits.RotateLeft32(x[1]+x[0], 9)
		x[3] ^= bits.RotateLeft32(x[2]+x[1], 13)
		x[0] ^= bits.RotateLeft32(x[3]+x[2], 18)

		x[6] ^= bits.RotateLeft32(x[5]+x[4], 7)
		x[7] ^= bits.RotateLeft32(x[6]+x[5], 9)
		x[4] ^= bits.RotateLeft32(x[7]+x[6], 13)
		x[5] ^= bits.RotateLeft32(x[4]+x[7], 18)

		x[11] ^= bits.RotateLeft32(x[10]+x[9], 7)
		x[8] ^= bits.RotateLeft32(x[11]+x[10], 9)
		x[9] ^= bits.RotateLeft32(x[8]+x[11], 13)
		x[10] ^= bits.RotateLeft32(x[9]+x[8], 18)

		x[12] ^= bits.RotateLeft32(x[15]+x[14], 7)
		x[13] ^= bits.RotateLeft32(x[12]+x[15], 9)
		x[14] ^= bits.RotateLeft32(x[13]+x[12], 13)
		x[15] ^= bits.RotateLeft32(x[14]+x[13], 18)
	}
	for i := 0; i < 16; i++ {
		b[i] += x[i*5%16]
	}
}

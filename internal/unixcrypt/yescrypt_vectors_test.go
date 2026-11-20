package unixcrypt

import "strings"

// yescryptVectors were produced by libxcrypt's crypt(3) (Perl's crypt on
// Debian 12). They cover the distribution default j9T (N=4096, r=32, which
// takes the prehash path), cheaper settings without the prehash, p and t
// parameters, the WORM and classic flavors, an empty, a 200-byte and a UTF-8
// password. The jD5.7 one is also in yescrypt's own TESTS-OK.
var yescryptVectors = []cryptVector{
	{"pleaseletmein", "$y$j9T$LdJMENpBABJJ3hIHjB1Bi.$iofk68xbXBoXKsxTyMBCh2qkQuzQZ2Zik521F9TsTq6"},
	{"", "$y$j9T$LdJMENpBABJJ3hIHjB1Bi.$0VoQRSq3WjXDU.r5dyEx3bs9lIvBVufPNCNqODXmIC8"},
	{"correct horse battery staple", "$y$j9T$3aXl0WCPDhZ7JZFH/NqW9/$BZAVK.lZG0l964HSxN81UVRTK8AHPAP.lyU6Norjhs5"},
	{"Hello world!", "$y$j75$saltsaltsaltsaltsalt..$yV5eLO3gNlU9v6pzxkwgPk44iniP5.vzmlDY/bGIA53"},
	{"Hello world!", "$y$jC5$abcdefghijklmnopqrstu.$d3cxKwE4Qtw2lW7SPh9H5dfNVkL8esiffyRRyMoFN32"},
	{"p and t", "$y$j750..$LdJMENpBABJJ3hIHjB1Bi.$BSfWHJoaYt095OBoFY4LOTMd9CrEolPG8eQkRl3DEsD"},
	{"time only", "$y$j75//$LdJMENpBABJJ3hIHjB1Bi.$g/aGu275MzUjvgKo5NnD6R8SH.5Z92hZwNjdQIAMbM7"},
	{"pleaseletmein", "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIugoNB6"},
	{"worm flavor", "$y$/75$LdJMENpBABJJ3hIHjB1Bi.$0GdrZWYpx2q1r0DHQCKHZyOreABf.1yRHZVT4h/.1q2"},
	{"classic flavor", "$y$.75$LdJMENpBABJJ3hIHjB1Bi.$MmEjYRC.u/aHxZMzHqlrJnVkE4rgsEpoRPylsgUUUZ1"},
	{"\xe5\xaf\x86\xe7\xa0\x81-utf8", "$y$j9T$q/VRxRA2hIHjB1Bi7ue6m0$CkcFrHGm1R/MvR36.wrgStFrwdZmseDPvGD.6EgZZr/"},
	{strings.Repeat("a", 200), "$y$j9T$LdJMENpBABJJ3hIHjB1Bi.$V4ewTPl5uPMV37aPFVg.L3lHqc/xCDtZyGZ2UVNFtL7"},
	{"r1", "$y$j7/$LdJMENpBABJJ3hIHjB1Bi.$ARbOhE1kpIhhkDBEwe6zatNKwt3reiEJ5fRYMU/COZ6"},
}

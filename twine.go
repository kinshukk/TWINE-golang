package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

var (
	sbox = map[int]int{
		0x0: 0xC,
		0x1: 0x0,
		0x2: 0xF,
		0x3: 0xA,
		0x4: 0x2,
		0x5: 0xB,
		0x6: 0x9,
		0x7: 0x5,
		0x8: 0x8,
		0x9: 0x3,
		0xA: 0xD,
		0xB: 0x7,
		0xC: 0x1,
		0xD: 0xE,
		0xE: 0x6,
		0xF: 0x4,
	}

	permutation_enc = map[int]int{
		0x0: 0x5,
		0x1: 0x0,
		0x2: 0x1,
		0x3: 0x4,
		0x4: 0x7,
		0x5: 0xC,
		0x6: 0x3,
		0x7: 0x8,
		0x8: 0xD,
		0x9: 0x6,
		0xA: 0x9,
		0xB: 0x2,
		0xC: 0xF,
		0xD: 0xA,
		0xE: 0xB,
		0xF: 0xE,
	}

	permutation_dec = map[int]int{
		0x0: 0x1,
		0x1: 0x2,
		0x2: 0xB,
		0x3: 0x6,
		0x4: 0x3,
		0x5: 0x0,
		0x6: 0x9,
		0x7: 0x4,
		0x8: 0x7,
		0x9: 0xA,
		0xA: 0xD,
		0xB: 0xE,
		0xC: 0x5,
		0xD: 0x8,
		0xE: 0xF,
		0xF: 0xC,
	}

	con = map[int]int{
		0x01: 0x01,
		0x02: 0x02,
		0x03: 0x04,
		0x04: 0x08,
		0x05: 0x10,
		0x06: 0x20,
		0x07: 0x03,
		0x08: 0x06,
		0x09: 0x0C,
		0x0A: 0x18,
		0x0B: 0x30,
		0x0C: 0x23,
		0x0D: 0x05,
		0x0E: 0x0A,
		0x0F: 0x14,
		0x10: 0x28,
		0x11: 0x13,
		0x12: 0x26,
		0x13: 0x0F,
		0x14: 0x1E,
		0x15: 0x3C,
		0x16: 0x3B,
		0x17: 0x35,
		0x18: 0x29,
		0x19: 0x11,
		0x1A: 0x22,
		0x1B: 0x07,
		0x1C: 0x0E,
		0x1D: 0x1C,
		0x1E: 0x38,
		0x1F: 0x33,
		0x20: 0x25,
		0x21: 0x09,
		0x22: 0x12,
		0x23: 0x24,
	}
)

func _S(i int) int {
	return sbox[i]
}

func _CON_L(r int) int {
	return con[r] & 0b111
}

func _CON_H(r int) int {
	return con[r] >> 3 & 0b111
}

func _Rot4(bits []int) []int {
	var rot = []int{bits[1], bits[2], bits[3], bits[0]}
	return rot
}
func _Rot16(bits []int) []int {
	var rot = []int{}
	for i := 4; i < 20; i++ {
		rot = append(rot, bits[i])
	}
	rot = append(rot, bits[0], bits[1], bits[2], bits[3])
	return rot
}

func _get_4_bits(source string, pos int) int {
	// pos = pos * 4
	// // var position uint = pos
	// source.Rsh(source, uint(pos))
	// last_4_bits := big.NewInt(0xF)
	// source.And(source, last_4_bits)
	// return int(source.Int64())

	for len(source) < 16 {
		source = "0" + source
	}
	pos += 1
	bits := source[pos-1 : pos]
	decimal, _ := strconv.ParseInt(bits, 16, 0)
	return int(decimal)
}

func _key_schedule_80(key string) [37][8]int {
	var RK_32 [37][8]int
	var WK_80 []int
	for i := 0; i < 20; i++ {
		WK_80 = append(WK_80, _get_4_bits(key, i))
	}
	for r := 1; r < 36; r++ {
		RK_32[r][0] = WK_80[1]
		RK_32[r][1] = WK_80[3]
		RK_32[r][2] = WK_80[4]
		RK_32[r][3] = WK_80[6]
		RK_32[r][4] = WK_80[13]
		RK_32[r][5] = WK_80[14]
		RK_32[r][6] = WK_80[15]
		RK_32[r][7] = WK_80[16]

		WK_80[1] = WK_80[1] ^ _S(WK_80[0])
		WK_80[4] = WK_80[4] ^ _S(WK_80[16])
		WK_80[7] = WK_80[7] ^ _CON_H(r)
		WK_80[19] = WK_80[19] ^ _CON_L(r)

		WK0_to_WK3_16 := []int{WK_80[0], WK_80[1], WK_80[2], WK_80[3]}
		WK0_to_WK3_16 = _Rot4(WK0_to_WK3_16)

		for j := 0; j <= 3; j++ {
			WK_80[j] = WK0_to_WK3_16[j]
		}

		var WK0_to_WK19_80 []int
		for j := 0; j < 20; j++ {
			WK0_to_WK19_80 = append(WK0_to_WK19_80, WK_80[j])
		}

		WK0_to_WK19_80 = _Rot16(WK0_to_WK19_80)
		for k := 0; k < 20; k++ {
			WK_80[k] = WK0_to_WK19_80[k]
		}
	}
	RK_32[36][0] = WK_80[1]
	RK_32[36][1] = WK_80[3]
	RK_32[36][2] = WK_80[4]
	RK_32[36][3] = WK_80[6]
	RK_32[36][4] = WK_80[13]
	RK_32[36][5] = WK_80[14]
	RK_32[36][6] = WK_80[15]
	RK_32[36][7] = WK_80[16]
	return RK_32
}

func _key_schedule_128(key string) [37][8]int {
	var RK_32 [37][8]int
	var WK_128 []int
	for i := 0; i < 32; i++ {
		WK_128 = append(WK_128, _get_4_bits(key, i))
	}
	for r := 1; r < 36; r++ {
		RK_32[r][0] = WK_128[2]
		RK_32[r][1] = WK_128[3]
		RK_32[r][2] = WK_128[12]
		RK_32[r][3] = WK_128[15]
		RK_32[r][4] = WK_128[17]
		RK_32[r][5] = WK_128[18]
		RK_32[r][6] = WK_128[28]
		RK_32[r][7] = WK_128[31]

		WK_128[1] = WK_128[1] ^ _S(WK_128[0])
		WK_128[4] = WK_128[4] ^ _S(WK_128[16])
		WK_128[23] = WK_128[23] ^ _S(WK_128[30])
		WK_128[7] = WK_128[7] ^ _CON_H(r)
		WK_128[19] = WK_128[19] ^ _CON_L(r)

		WK0_to_WK3_16 := []int{WK_128[0], WK_128[1], WK_128[2], WK_128[3]}
		WK0_to_WK3_16 = _Rot4(WK0_to_WK3_16)

		for j := 0; j <= 3; j++ {
			WK_128[j] = WK0_to_WK3_16[j]
		}

		var WK0_to_WK31_128 []int
		for j := 0; j < 32; j++ {
			WK0_to_WK31_128 = append(WK0_to_WK31_128, WK_128[j])
		}

		WK0_to_WK31_128 = _Rot16(WK0_to_WK31_128)
		for k := 0; k < 32; k++ {
			WK_128[k] = WK0_to_WK31_128[k]
		}
	}
	RK_32[36][0] = WK_128[2]
	RK_32[36][1] = WK_128[3]
	RK_32[36][2] = WK_128[12]
	RK_32[36][3] = WK_128[15]
	RK_32[36][4] = WK_128[17]
	RK_32[36][5] = WK_128[18]
	RK_32[36][6] = WK_128[28]
	RK_32[36][7] = WK_128[31]
	return RK_32
}

func _encrypt(P string, RK [37][8]int) string {
	RK_32 := RK
	var X_16 [37][16]int
	var C string
	for i := 0; i < 16; i++ {
		X_16[1][i] = _get_4_bits(P, i)
	}

	for i := 1; i < 36; i++ {
		for j := 0; j < 8; j++ {
			X_16[i][(2*j)+1] = _S(X_16[i][2*j]^RK_32[i][j]) ^ X_16[i][2*j+1]
		}
		for h := 0; h < 16; h++ {
			X_16[i+1][permutation_enc[h]] = X_16[i][h]
		}
	}

	for j := 0; j < 8; j++ {
		X_16[36][2*j+1] = _S(X_16[36][2*j]^RK_32[36][j]) ^ X_16[36][2*j+1]
	}

	for j := 0; j < 16; j++ {
		hex := fmt.Sprintf("%X", X_16[36][j])
		C = C + hex
	}

	return C
}

func _decrypt(C string, RK [37][8]int) string {
	RK_32 := RK
	var X_16 [37][16]int
	var P string
	for i := 0; i < 16; i++ {
		X_16[36][i] = _get_4_bits(C, i)
	}

	for i := 36; i > 1; i-- {
		for j := 0; j < 8; j++ {
			X_16[i][(2*j)+1] = _S(X_16[i][2*j]^RK_32[i][j]) ^ X_16[i][(2*j)+1]
		}
		for h := 0; h < 16; h++ {
			X_16[i-1][permutation_dec[h]] = X_16[i][h]
		}
	}

	for j := 0; j < 8; j++ {
		X_16[1][2*j+1] = _S(X_16[1][2*j]^RK_32[1][j]) ^ X_16[1][2*j+1]
	}

	for j := 0; j < 16; j++ {
		hex := fmt.Sprintf("%X", X_16[1][j])
		P = P + hex
	}

	// Remove leading zeros
	for true {
		if strings.HasPrefix(P, "0") {
			P = strings.Replace(P, "0", "", 1)
		} else {
			break
		}
	}

	return P
}

func encrypt(P, key string, keySize int) string {
	hexFormat := hex.EncodeToString([]byte(P))
	key = hex.EncodeToString([]byte(key))
	iterations := math.Ceil(float64(len(hexFormat)) / 16.0)
	C := ""

	for i := 0; i < int(iterations); i++ {
		block := hexFormat[(16 * i):int(math.Min(float64((16*i)+16), float64(len(hexFormat))))]

		if keySize == 80 {
			C = C + _encrypt(block, _key_schedule_80(key))
		} else if keySize == 128 {
			C = C + _encrypt(block, _key_schedule_128(key))
		} else {
			fmt.Println("Invalid Key Size")
		}
	}
	return C
}

func decrypt(C, key string, keySize int) string {
	key = hex.EncodeToString([]byte(key))
	iterationsD := math.Ceil(float64(len(C)) / 16.0)
	P := ""

	for i := 0; i < int(iterationsD); i++ {
		block := C[(16 * i):int(math.Min(float64((16*i)+16), float64(len(C))))]
		if keySize == 80 {
			P = P + _decrypt(block, _key_schedule_80(key))
		} else if keySize == 128 {
			P = P + _decrypt(block, _key_schedule_128(key))
		}
	}
	Deciphered_text, _ := hex.DecodeString(P)
	return string(Deciphered_text)
}
func checkKey(key string) bool {
	if len(key) == 10 || len(key) == 16 {
		return true
	} else {
		return false
	}
}
func main() {

	var eOrD string
	var keySize int
	var key string
	fmt.Println("Press E to Encrypt or D to decrypt")
	fmt.Scanln(&eOrD)
	fmt.Println("Enter key size 80 or 128")
	fmt.Scanln(&keySize)

	if eOrD == "E" || eOrD == "e" {
		var P string
		fmt.Println("Enter Plain text")
		in := bufio.NewReader(os.Stdin)
		P, _ = in.ReadString('\n')
		fmt.Println("Enter Key")
		fmt.Scanln(&key)
		if !(checkKey(key)) {
			fmt.Println("Incorrect key length, please enter 10 char for 80 bits or 16 char for 128 bits")
			os.Exit(1)
		}
		fmt.Println("Cipher Text", encrypt(P, key, keySize))

	} else if eOrD == "D" || eOrD == "d" {
		var C string
		fmt.Println("Enter Cipher Text")
		fmt.Scanln(&C)
		fmt.Println("Enter Key")
		fmt.Scanln(&key)
		if !(checkKey(key)) {
			fmt.Println("Incorrect key length, please enter 10 char for 80 bits or 16 char for 128 bits")
			os.Exit(1)
		}
		fmt.Println("Plain Text", decrypt(C, key, keySize))
	} else {
		fmt.Println("Invalid Input")
	}
	// fmt.Println(encrypt("h", "<o8~I{?3Uz", 80))
	// fmt.Println(decrypt("9843612ECAE79496", "<o8~I{?3Uz", 80))
	// fmt.Println("encdec", decrypt(encrypt("hello", "<o8~I{?3Uz", 80), "<o8~I{?3Uz", 80))
	// fmt.Println("cipher", _decrypt("9843612ECAE79496", _key_schedule_80("3c6f387e497b3f33557a")))l
}

// fmt.Println(hex, reflect.TypeOf(hex))
// fmt.Println("cipher text", _encrypt("68", _key_schedule_80("3c6f387e497b3f33557a")))
// fmt.Println("plain text", _decrypt(_encrypt("1234567890123456", _key_schedule_80("3c6f387e497b3f33557a")), _key_schedule_80("3c6f387e497b3f33557a")))
// fmt.Println("plain text", _decrypt("27520ACEE7F0EA0D", _key_schedule_80("3c6f387e497b3f33557a")))
// C = C + hex
// fmt.Println(C, reflect.TypeOf(C))
// fmt.Println(_Rot16(test_rot))
// output, err = strconv.ParseInt("3c6f387e497b3f33557a")
// var key, ok = new(big.Int).SetString("3c6f387e497b3f33557a", 16)
// fmt.Println(_get_4_bits(key, 4))
// fmt.Println(ok, key)
// key := big.Int(0x3c6f387e497b3f33557a)
// var key big.Int = 0x3c6f387e497b3f33557a
// var key, ok = new(big.Int).SetString("3c6f387e497b3f33557a", 16)
// fmt.Println(key, ok, typeof)
// fmt.Println(_key_schedule_80(key))

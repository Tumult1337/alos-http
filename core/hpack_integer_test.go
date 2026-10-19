package core

import (
	"fmt"
	"math/big"
	"testing"
)

func hpackIntegerBytes(value *big.Int, prefixBits uint8, flags byte) []byte {
	prefixMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(prefixBits)), big.NewInt(1))
	remaining := new(big.Int).Set(value)
	if remaining.Cmp(prefixMax) < 0 {
		return []byte{flags | byte(remaining.Uint64())}
	}
	encoded := []byte{flags | byte(prefixMax.Uint64())}
	remaining.Sub(remaining, prefixMax)
	divisor := big.NewInt(128)
	for {
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(remaining, divisor, remainder)
		digit := byte(remainder.Uint64())
		if quotient.Sign() == 0 {
			return append(encoded, digit)
		}
		encoded = append(encoded, digit|0x80)
		remaining = quotient
	}
}

func hpackIntegerOracle(data []byte, prefixBits uint8) (uint64, int) {
	if prefixBits == 0 || prefixBits > 8 || len(data) == 0 {
		return 0, 0
	}
	prefixMax := uint64(1)<<prefixBits - 1
	first := uint64(data[0]) % (prefixMax + 1)
	if first != prefixMax {
		return first, 1
	}
	value := new(big.Int).SetUint64(first)
	factor := big.NewInt(1)
	for position := 1; position < len(data) && position <= 10; position++ {
		digit := big.NewInt(int64(data[position] % 128))
		value.Add(value, digit.Mul(digit, factor))
		if !value.IsUint64() {
			return 0, 0
		}
		if data[position] < 128 {
			return value.Uint64(), position + 1
		}
		factor.Mul(factor, big.NewInt(128))
	}
	return 0, 0
}

func TestHpackDecodeIntScalarBoundaries(t *testing.T) {
	for prefixBits := uint8(1); prefixBits <= 8; prefixBits++ {
		prefixMax := uint64(1)<<prefixBits - 1
		values := []uint64{0, 1, prefixMax - 1, prefixMax, prefixMax + 1, 127, 128, 255, 256, 1 << 63, ^uint64(0) - 1, ^uint64(0)}
		for flags := 0; flags < 256; flags += 1 << prefixBits {
			for _, value := range values {
				t.Run(fmt.Sprintf("prefix%d/flags%d/value%d", prefixBits, flags, value), func(t *testing.T) {
					encoded := hpackIntegerBytes(new(big.Int).SetUint64(value), prefixBits, byte(flags))
					wantValue, wantConsumed := hpackIntegerOracle(encoded, prefixBits)
					if wantValue != value || wantConsumed != len(encoded) {
						t.Fatalf("oracle decoded (%d, %d), want (%d, %d)", wantValue, wantConsumed, value, len(encoded))
					}
					encoded = append(encoded, 0xff, 0x01)
					if gotValue, gotConsumed := HpackDecodeInt(encoded, prefixBits); gotValue != wantValue || gotConsumed != wantConsumed {
						t.Fatalf("decoded (%d, %d), want (%d, %d)", gotValue, gotConsumed, wantValue, wantConsumed)
					}
					for length := 0; length < wantConsumed; length++ {
						if gotValue, gotConsumed := HpackDecodeInt(encoded[:length], prefixBits); gotValue != 0 || gotConsumed != 0 {
							t.Fatalf("truncated length %d decoded (%d, %d), want (0, 0)", length, gotValue, gotConsumed)
						}
					}
				})
			}
		}
	}
}

func TestHpackDecodeIntInvalidPrefix(t *testing.T) {
	for _, prefixBits := range []uint8{0, 9, 63, 64, 255} {
		t.Run(fmt.Sprintf("prefix%d", prefixBits), func(t *testing.T) {
			if value, consumed := HpackDecodeInt([]byte{0, 0}, prefixBits); value != 0 || consumed != 0 {
				t.Fatalf("invalid prefix decoded (%d, %d), want (0, 0)", value, consumed)
			}
		})
	}
}

func TestHpackDecodeIntOverflow(t *testing.T) {
	for prefixBits := uint8(1); prefixBits <= 8; prefixBits++ {
		prefixMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(prefixBits)), big.NewInt(1))
		values := map[string]*big.Int{
			"addition": new(big.Int).Lsh(big.NewInt(1), 64),
			"shift":    new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), prefixMax),
		}
		for name, value := range values {
			t.Run(fmt.Sprintf("prefix%d/%s", prefixBits, name), func(t *testing.T) {
				encoded := hpackIntegerBytes(value, prefixBits, 0)
				if wantValue, wantConsumed := hpackIntegerOracle(encoded, prefixBits); wantValue != 0 || wantConsumed != 0 {
					t.Fatalf("oracle accepted overflow (%d, %d)", wantValue, wantConsumed)
				}
				if gotValue, gotConsumed := HpackDecodeInt(encoded, prefixBits); gotValue != 0 || gotConsumed != 0 {
					t.Fatalf("overflow decoded (%d, %d), want (0, 0)", gotValue, gotConsumed)
				}
			})
		}
	}
}

func TestHpackDecodeIntZeroExtensionBound(t *testing.T) {
	for prefixBits := uint8(1); prefixBits <= 8; prefixBits++ {
		prefixMax := byte(uint16(1)<<prefixBits - 1)
		for groups := 1; groups <= 12; groups++ {
			t.Run(fmt.Sprintf("prefix%d/groups%d", prefixBits, groups), func(t *testing.T) {
				encoded := make([]byte, groups+1)
				encoded[0] = prefixMax
				for position := 1; position < groups; position++ {
					encoded[position] = 0x80
				}
				wantValue, wantConsumed := hpackIntegerOracle(encoded, prefixBits)
				if gotValue, gotConsumed := HpackDecodeInt(encoded, prefixBits); gotValue != wantValue || gotConsumed != wantConsumed {
					t.Fatalf("decoded (%d, %d), want (%d, %d)", gotValue, gotConsumed, wantValue, wantConsumed)
				}
			})
		}
	}
}

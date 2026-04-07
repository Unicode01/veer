//go:build linux

package app

import "testing"

func TestBuildKernelEgressWildcardMaps(t *testing.T) {
	egressSafe := preparedKernelRule{
		key: tcRuleKeyV4{
			IfIndex: 1,
			DstAddr: 0,
			DstPort: 0,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:     11,
			Flags:      kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT,
			OutIfIndex: 9,
			NATAddr:    123,
		},
	}
	egressUnsafe := preparedKernelRule{
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstAddr: 0,
			DstPort: 0,
			Proto:   17,
		},
		value: tcRuleValueV4{
			RuleID:     22,
			Flags:      kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT,
			OutIfIndex: 8,
			NATAddr:    456,
		},
	}

	fast := buildKernelEgressWildcardFastMap([]preparedKernelRule{
		egressSafe,
		{
			key: tcRuleKeyV4{
				IfIndex: 1,
				DstAddr: 0x01020304,
				DstPort: 443,
				Proto:   6,
			},
			value: tcRuleValueV4{RuleID: 12},
		},
		egressUnsafe,
		{
			key: tcRuleKeyV4{
				IfIndex: 2,
				DstAddr: 0,
				DstPort: 53,
				Proto:   17,
			},
			value: tcRuleValueV4{RuleID: 23},
		},
	})

	safeKey := kernelEgressWildcardMapKey(1, 6)
	unsafeKey := kernelEgressWildcardMapKey(2, 17)

	if fast[safeKey] != 1 {
		t.Fatalf("fast[safeKey] = %d, want 1", fast[safeKey])
	}
	if _, ok := fast[unsafeKey]; ok {
		t.Fatal("fast map unexpectedly contains unsafe wildcard key")
	}
}

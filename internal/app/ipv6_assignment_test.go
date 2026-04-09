package app

import "testing"

func TestClassifyIPv6AssignmentIntent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		prefix   string
		wantKind string
		wantMode string
	}{
		{
			name:     "single address",
			prefix:   "2402:db8::10/128",
			wantKind: ipv6AssignmentIntentSingleAddress,
			wantMode: ipv6AssignmentAddressingStatic,
		},
		{
			name:     "delegated /64",
			prefix:   "2402:db8:1::/64",
			wantKind: ipv6AssignmentIntentDelegatedPrefix,
			wantMode: ipv6AssignmentAddressingSLAACRecommended,
		},
		{
			name:     "delegated /80",
			prefix:   "2402:db8:1:100::/80",
			wantKind: ipv6AssignmentIntentDelegatedPrefix,
			wantMode: ipv6AssignmentAddressingManualDelegation,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, prefix, err := normalizeIPv6Prefix(tc.prefix)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(%q) error = %v", tc.prefix, err)
			}

			got := classifyIPv6AssignmentIntent(prefix)
			if got.kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", got.kind, tc.wantKind)
			}
			if got.addressing != tc.wantMode {
				t.Fatalf("addressing = %q, want %q", got.addressing, tc.wantMode)
			}
		})
	}
}

func TestRebaseIPv6PrefixWithinParent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		storedParent  string
		currentParent string
		assigned      string
		want          string
	}{
		{
			name:          "single address preserves host bits",
			storedParent:  "2402:db8:100::/64",
			currentParent: "2402:db8:200::/64",
			assigned:      "2402:db8:100::1234/128",
			want:          "2402:db8:200::1234/128",
		},
		{
			name:          "delegated prefix preserves subnet id",
			storedParent:  "2402:db8:100::/56",
			currentParent: "2402:db8:200::/56",
			assigned:      "2402:db8:100:23::/64",
			want:          "2402:db8:200:23::/64",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, storedParent, err := normalizeIPv6Prefix(tc.storedParent)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(stored) error = %v", err)
			}
			_, currentParent, err := normalizeIPv6Prefix(tc.currentParent)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(current) error = %v", err)
			}
			_, assigned, err := normalizeIPv6Prefix(tc.assigned)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(assigned) error = %v", err)
			}

			got, err := rebaseIPv6PrefixWithinParent(storedParent, currentParent, assigned)
			if err != nil {
				t.Fatalf("rebaseIPv6PrefixWithinParent() error = %v", err)
			}
			if got.String() != tc.want {
				t.Fatalf("rebaseIPv6PrefixWithinParent() = %q, want %q", got.String(), tc.want)
			}
		})
	}
}

func TestSelectCurrentIPv6ParentPrefixPrefersSamePrefixClass(t *testing.T) {
	t.Parallel()

	_, storedPublic, err := normalizeIPv6Prefix("240e:390:6cee:f540::/64")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(public stored) error = %v", err)
	}
	_, storedULA, err := normalizeIPv6Prefix("fd7b:90b5:394d::/64")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(ula stored) error = %v", err)
	}

	iface := HostNetworkInterface{
		Name: "eno1",
		Addresses: []HostInterfaceAddress{
			{
				Family:    ipFamilyIPv6,
				IP:        "240e:390:6cee:f541::1",
				CIDR:      "240e:390:6cee:f541::/64",
				PrefixLen: 64,
			},
			{
				Family:    ipFamilyIPv6,
				IP:        "fd7b:90b5:394d:1::1",
				CIDR:      "fd7b:90b5:394d:1::/64",
				PrefixLen: 64,
			},
		},
	}

	gotText, gotPrefix, err := selectCurrentIPv6ParentPrefix(iface, storedPublic)
	if err != nil {
		t.Fatalf("selectCurrentIPv6ParentPrefix(public) error = %v", err)
	}
	if gotText != "240e:390:6cee:f541::/64" || gotPrefix.String() != "240e:390:6cee:f541::/64" {
		t.Fatalf("selectCurrentIPv6ParentPrefix(public) = %q / %v, want 240e:390:6cee:f541::/64", gotText, gotPrefix)
	}

	gotText, gotPrefix, err = selectCurrentIPv6ParentPrefix(iface, storedULA)
	if err != nil {
		t.Fatalf("selectCurrentIPv6ParentPrefix(ula) error = %v", err)
	}
	if gotText != "fd7b:90b5:394d:1::/64" || gotPrefix.String() != "fd7b:90b5:394d:1::/64" {
		t.Fatalf("selectCurrentIPv6ParentPrefix(ula) = %q / %v, want fd7b:90b5:394d:1::/64", gotText, gotPrefix)
	}
}

func TestIPv6PrefixesOverlap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "same prefix", a: "2001:db8::/64", b: "2001:db8::/64", want: true},
		{name: "delegated child overlaps parent", a: "2001:db8::/64", b: "2001:db8::1234/128", want: true},
		{name: "parent order reversed", a: "2001:db8::1234/128", b: "2001:db8::/64", want: true},
		{name: "different subnets do not overlap", a: "2001:db8::/64", b: "2001:db8:1::/64", want: false},
		{name: "different delegated prefixes do not overlap", a: "2001:db8:1::/80", b: "2001:db8:1:1::/80", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, a, err := normalizeIPv6Prefix(tc.a)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(a) error = %v", err)
			}
			_, b, err := normalizeIPv6Prefix(tc.b)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(b) error = %v", err)
			}
			if got := ipv6PrefixesOverlap(a, b); got != tc.want {
				t.Fatalf("ipv6PrefixesOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

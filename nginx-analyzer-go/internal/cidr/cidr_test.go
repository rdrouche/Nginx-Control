package cidr

import (
	"reflect"
	"testing"
)

func TestIPv4(t *testing.T) {
	if !IpInCidr("203.0.113.5", "203.0.113.0/24") {
		t.Error("appartenance a un bloc /24")
	}
	if IpInCidr("203.0.114.5", "203.0.113.0/24") {
		t.Error("hors du bloc")
	}
	if !IpInCidr("203.0.113.5", "203.0.113.5/32") {
		t.Error("bloc /32 = adresse exacte")
	}
	if !IpInCidr("203.0.113.5", "203.0.113.5") {
		t.Error("sans prefixe = exact (match)")
	}
	if IpInCidr("203.0.113.5", "203.0.113.6") {
		t.Error("sans prefixe = exact (no match)")
	}
	if !IpInCidr("1.2.3.4", "0.0.0.0/0") {
		t.Error("/0 englobe toute adresse v4")
	}
	if !IpInCidr("10.0.0.0", "10.0.0.0/8") || !IpInCidr("10.255.255.255", "10.0.0.0/8") || IpInCidr("11.0.0.0", "10.0.0.0/8") {
		t.Error("frontiere de bloc respectee")
	}
	if !IpInCidr("192.168.1.5", "192.168.0.0/20") || IpInCidr("192.168.16.5", "192.168.0.0/20") {
		t.Error("prefixe non multiple de 8")
	}
}

func TestIPv6(t *testing.T) {
	if !IpInCidr("2001:db8::1", "2001:db8::/32") {
		t.Error("appartenance a un bloc /32")
	}
	if IpInCidr("2001:db9::1", "2001:db8::/32") {
		t.Error("hors du bloc")
	}
	if !IpInCidr("::1", "::1") {
		t.Error("adresse exacte sans prefixe")
	}
	a := Ipv6ToBytes("2001:db8::1")
	b := Ipv6ToBytes("2001:0db8:0000:0000:0000:0000:0000:0001")
	if !reflect.DeepEqual(a, b) {
		t.Errorf("compression :: mal decompressee: %v vs %v", a, b)
	}
	r := ToBytes("::ffff:203.0.113.5")
	if r == nil || r.Family != 6 {
		t.Fatalf("adresse IPv4-mappee: %v", r)
	}
	if !reflect.DeepEqual(r.Bytes[len(r.Bytes)-4:], []byte{203, 0, 113, 5}) {
		t.Errorf("suffixe v4 incorrect: %v", r.Bytes)
	}
}

func TestFamilyIsolation(t *testing.T) {
	if IpInCidr("1.2.3.4", "::1/128") {
		t.Error("v4 ne doit jamais appartenir a un bloc v6")
	}
	if IpInCidr("::1", "1.2.3.4/32") {
		t.Error("v6 ne doit jamais appartenir a un bloc v4")
	}
}

func TestMappedV4Addresses(t *testing.T) {
	if !IpInCidr("::ffff:203.0.113.5", "203.0.113.0/24") {
		t.Error("::ffff:a.b.c.d doit matcher un bloc v4 qui la contient")
	}
	if IpInCidr("::ffff:203.0.113.5", "203.0.114.0/24") {
		t.Error("::ffff:a.b.c.d hors bloc")
	}
	if !IpInCidr("::ffff:203.0.113.5", "203.0.113.5") {
		t.Error("::ffff:a.b.c.d exacte == adresse v4 nue")
	}
	if IpInCidr("2001:db8::1", "0.0.0.0/0") {
		t.Error("une v6 non mappee ne doit jamais matcher un bloc v4")
	}
	if !IpInCidr("203.0.113.5", "::ffff:203.0.113.0/120") {
		t.Error("v4 nue doit matcher un bloc v6-mappe qui la contient")
	}
	if IpInCidr("203.0.114.5", "::ffff:203.0.113.0/120") {
		t.Error("v4 nue hors bloc v6-mappe")
	}
	if IpInCidr("203.0.113.5", "::ffff:203.0.113.0/64") {
		t.Error("bloc v6-mappe avec moins de 96 bits fixes ne doit pas se ramener a v4")
	}
}

func TestRobustness(t *testing.T) {
	cases := []struct{ ip, pat string }{
		{"", ""},
		{"pas-une-ip", "0.0.0.0/0"},
		{"999.1.1.1", "0.0.0.0/0"},
		{"", "/24"},
		{"1.2.3.4", "1.2.3.4/99"},
		{"::1", "::1/999"},
		{"1.2.3.4", "1.2.3.4/-1"},
		{"1::2::3", "1::2::3/64"},
	}
	for _, c := range cases {
		if IpInCidr(c.ip, c.pat) {
			t.Errorf("IpInCidr(%q, %q) should be false", c.ip, c.pat)
		}
	}
}

func TestExtraWhitespace(t *testing.T) {
	if !IsValidPattern("203.0.113.0/24 ") {
		t.Error("espace final apres le prefixe")
	}
	if !IpInCidr("203.0.113.5", "203.0.113.0/24 ") {
		t.Error("espace final ne doit pas invalider le match")
	}
	if !IsValidPattern(" 203.0.113.0/24") {
		t.Error("espace au debut")
	}
	if !IsValidPattern("2001:db8::/32 ") {
		t.Error("espace final v6")
	}
}

func TestIsValidPattern(t *testing.T) {
	if !IsValidPattern("203.0.113.5") {
		t.Error("adresse simple valide")
	}
	if !IsValidPattern("203.0.113.0/24") {
		t.Error("CIDR valide")
	}
	if !IsValidPattern("2001:db8::/32") {
		t.Error("CIDR v6 valide")
	}
	if IsValidPattern("pas-une-ip") || IsValidPattern("1.2.3.4/33") || IsValidPattern("") {
		t.Error("motif invalide doit etre rejete")
	}
}

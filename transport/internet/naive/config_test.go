package naive

import "testing"

// TestParseNetwork pins the spelling shared by settings.network, naiveSettings
// and the outbound. The empty and unrecognised cases are the ones that matter:
// they mean BOTH, not tcp, and a hand-edited config is the likeliest source of
// them.
func TestParseNetwork(t *testing.T) {
	cases := []struct {
		in       string
		tcp, udp bool
	}{
		{"tcp", true, false},
		{"udp", false, true},
		{"tcp,udp", true, true},
		{"udp,tcp", true, true},
		{" TCP , UDP ", true, true},
		{"h2", true, false},
		{"h3", false, true},
		{"quic", false, true},
		{"", true, true},
		{"nonsense", true, true},
		{",", true, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			tcp, udp := ParseNetwork(c.in)
			if tcp != c.tcp || udp != c.udp {
				t.Fatalf("ParseNetwork(%q) = (%v, %v), want (%v, %v)", c.in, tcp, udp, c.tcp, c.udp)
			}
		})
	}
}

// TestConfigMode covers the nil receiver, which is what a stream config with no
// naiveSettings block produces.
func TestConfigMode(t *testing.T) {
	var nilConfig *Config
	if mode := nilConfig.mode(); !mode.tcp || !mode.udp {
		t.Fatalf("a nil config must listen on both wires, got %+v", mode)
	}
	if mode := (&Config{Network: "udp"}).mode(); mode.tcp || !mode.udp {
		t.Fatalf(`Network "udp" must be h3 only, got %+v`, mode)
	}
}

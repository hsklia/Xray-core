package conf

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

// AnyTLSPaddingScheme is the padding scheme as it is written in config: either a
// list of scheme lines, or one raw multi-line string. It is not a StringList
// because that splits a plain string on commas, which a scheme line contains.
type AnyTLSPaddingScheme string

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (s *AnyTLSPaddingScheme) UnmarshalJSON(data []byte) error {
	var lines []string
	if err := json.Unmarshal(data, &lines); err == nil {
		*s = AnyTLSPaddingScheme(strings.Join(lines, "\n"))
		return nil
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err == nil {
		*s = AnyTLSPaddingScheme(raw)
		return nil
	}
	return errors.New("unknown format of AnyTLS padding scheme: " + string(data))
}

// AnyTLSUserConfig is user configuration
type AnyTLSUserConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// AnyTLSInboundFallback is fallback configuration
type AnyTLSInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

// AnyTLSServerConfig is Inbound configuration
type AnyTLSServerConfig struct {
	Clients       []*AnyTLSUserConfig      `json:"clients"`
	PaddingScheme AnyTLSPaddingScheme      `json:"paddingScheme"`
	Fallbacks     []*AnyTLSInboundFallback `json:"fallbacks"`
}

// Build implements Buildable
func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	config := &anytls.ServerConfig{
		Users:         make([]*protocol.User, len(c.Clients)),
		PaddingScheme: string(c.PaddingScheme),
	}

	for idx, rawUser := range c.Clients {
		if rawUser.Password == "" {
			return nil, errors.New("AnyTLS password is not specified for user ", rawUser.Email)
		}
		config.Users[idx] = &protocol.User{
			Level: uint32(rawUser.Level),
			Email: rawUser.Email,
			Account: serial.ToTypedMessage(&anytls.Account{
				Password: rawUser.Password,
			}),
		}
	}

	for _, fb := range c.Fallbacks {
		var i uint16
		var s string
		if err := json.Unmarshal(fb.Dest, &i); err == nil {
			s = strconv.Itoa(int(i))
		} else {
			_ = json.Unmarshal(fb.Dest, &s)
		}
		config.Fallbacks = append(config.Fallbacks, &anytls.Fallback{
			Name: fb.Name,
			Alpn: fb.Alpn,
			Path: fb.Path,
			Type: fb.Type,
			Dest: s,
			Xver: fb.Xver,
		})
	}
	for _, fb := range config.Fallbacks {
		if fb.Path != "" && fb.Path[0] != '/' {
			return nil, errors.New(`AnyTLS fallbacks: "path" must be empty or start with "/"`)
		}
		if fb.Type == "" && fb.Dest != "" {
			if filepath.IsAbs(fb.Dest) || fb.Dest[0] == '@' {
				fb.Type = "unix"
				if strings.HasPrefix(fb.Dest, "@@") && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path)) // may need padding to work with haproxy
					copy(fullAddr, fb.Dest[1:])
					fb.Dest = string(fullAddr)
				}
			} else {
				if _, err := strconv.Atoi(fb.Dest); err == nil {
					fb.Dest = "localhost:" + fb.Dest
				}
				if _, _, err := net.SplitHostPort(fb.Dest); err == nil {
					fb.Type = "tcp"
				}
			}
		}
		if fb.Type == "" {
			return nil, errors.New(`AnyTLS fallbacks: please fill in a valid value for every "dest"`)
		}
		if fb.Xver > 2 {
			return nil, errors.New(`AnyTLS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
	}

	return config, nil
}

// AnyTLSServerTarget is configuration of a single anytls server
type AnyTLSServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
}

// AnyTLSClientConfig is Outbound configuration
type AnyTLSClientConfig struct {
	Address  *Address              `json:"address"`
	Port     uint16                `json:"port"`
	Level    byte                  `json:"level"`
	Email    string                `json:"email"`
	Password string                `json:"password"`
	Servers  []*AnyTLSServerTarget `json:"servers"`

	// Seconds. Zero leaves the library defaults in place.
	IdleSessionCheckInterval uint32 `json:"idleSessionCheckInterval"`
	IdleSessionTimeout       uint32 `json:"idleSessionTimeout"`
	MinIdleSession           int32  `json:"minIdleSession"`
	DisableReuse             bool   `json:"disableReuse"`
}

// Build implements Buildable
func (c *AnyTLSClientConfig) Build() (proto.Message, error) {
	if c.Address != nil {
		c.Servers = []*AnyTLSServerTarget{
			{
				Address:  c.Address,
				Port:     c.Port,
				Level:    c.Level,
				Email:    c.Email,
				Password: c.Password,
			},
		}
	}
	if len(c.Servers) != 1 {
		return nil, errors.New(`AnyTLS settings: "servers" should have one and only one member. Multiple endpoints in "servers" should use multiple AnyTLS outbounds and routing balancer instead`)
	}

	rec := c.Servers[0]
	if rec.Address == nil {
		return nil, errors.New("AnyTLS server address is not set.")
	}
	if rec.Port == 0 {
		return nil, errors.New("Invalid AnyTLS port.")
	}
	if rec.Password == "" {
		return nil, errors.New("AnyTLS password is not specified.")
	}

	return &anytls.ClientConfig{
		Address:                  rec.Address.Build(),
		Port:                     uint32(rec.Port),
		Password:                 rec.Password,
		Email:                    rec.Email,
		Level:                    int32(rec.Level),
		IdleSessionCheckInterval: c.IdleSessionCheckInterval,
		IdleSessionTimeout:       c.IdleSessionTimeout,
		MinIdleSession:           c.MinIdleSession,
		DisableReuse:             c.DisableReuse,
	}, nil
}

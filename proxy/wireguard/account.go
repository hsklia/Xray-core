package wireguard

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount reuses PeerConfig on the wire. Its private, validated copy must
// not change after it has been admitted to a running WireGuard device.
type MemoryAccount struct {
	peer     *PeerConfig
	prefixes []netip.Prefix
}

// AsAccount implements protocol.AsAccount without adding a second protobuf
// representation of exactly the same WireGuard peer.
func (p *PeerConfig) AsAccount() (protocol.Account, error) {
	if p == nil {
		return nil, fmt.Errorf("WireGuard peer account is missing")
	}
	peer := proto.Clone(p).(*PeerConfig)
	var err error
	peer.PublicKey, err = accountKey(peer.PublicKey, false)
	if err != nil {
		return nil, fmt.Errorf("invalid WireGuard public key: %w", err)
	}
	peer.PreSharedKey, err = accountKey(peer.PreSharedKey, true)
	if err != nil {
		return nil, fmt.Errorf("invalid WireGuard preshared key: %w", err)
	}
	if peer.KeepAlive > 65535 {
		return nil, fmt.Errorf("WireGuard keepalive exceeds 65535 seconds")
	}
	if len(peer.AllowedIps) == 0 {
		return nil, fmt.Errorf("WireGuard peer needs at least one allowed IP")
	}
	prefixes := make([]netip.Prefix, 0, len(peer.AllowedIps))
	allowed := make([]string, 0, len(peer.AllowedIps))
	seen := make(map[netip.Prefix]bool, len(peer.AllowedIps))
	for _, value := range peer.AllowedIps {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid WireGuard allowed IP")
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
			allowed = append(allowed, prefix.String())
		}
	}
	sort.Strings(allowed)
	peer.AllowedIps = allowed
	return &MemoryAccount{peer: peer, prefixes: prefixes}, nil
}

// configuredPeerAccount indexes a peer that BuildDevice has already accepted.
// Older configurations can contain inert peers without any allowed IPs (or a
// zero key); introducing the management API must not prevent them from loading.
// Only new live accounts are subject to AsAccount's stricter validation.
func configuredPeerAccount(p *PeerConfig) *MemoryAccount {
	peer := proto.Clone(p).(*PeerConfig)
	peer.PublicKey = strings.ToLower(peer.PublicKey)
	peer.PreSharedKey = strings.ToLower(peer.PreSharedKey)
	if strings.Trim(peer.PreSharedKey, "0") == "" {
		peer.PreSharedKey = ""
	}
	account := &MemoryAccount{peer: peer}
	allowed := make([]string, 0, len(peer.AllowedIps))
	seen := make(map[netip.Prefix]bool, len(peer.AllowedIps))
	for _, value := range peer.AllowedIps {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue // The original UAPI has already checked every active prefix.
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			account.prefixes = append(account.prefixes, prefix)
			allowed = append(allowed, prefix.String())
		}
	}
	sort.Strings(allowed)
	peer.AllowedIps = allowed
	return account
}

func accountKey(value string, allowEmpty bool) (string, error) {
	if value == "" && allowEmpty {
		return "", nil
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("expected a 32-byte hex key")
	}
	if strings.Trim(value, "0") == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("public key cannot be zero")
	}
	return hex.EncodeToString(key), nil
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a != nil && b != nil && proto.Equal(a.peer, b.peer)
}

func (a *MemoryAccount) ToProto() proto.Message {
	return proto.Clone(a.peer)
}

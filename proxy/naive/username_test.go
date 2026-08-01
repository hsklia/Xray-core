package naive_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/naive"
	tcpserver "github.com/xtls/xray-core/testing/servers/tcp"
)

// testClient mirrors the shape infra/conf.NaiveUserConfig binds, so these tests
// exercise the same JSON the panel writes.
type testClient struct {
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

func settingsWithClients(clients ...testClient) string {
	b, err := json.Marshal(clients)
	if err != nil {
		panic(err)
	}
	return `{"clients": ` + string(b) + `, "network": "tcp", "masquerade": {"type": "404"}}`
}

// connectStatus runs one CONNECT with an explicit Basic credential and reports
// the status the inbound answered with. 200 means authenticated, 407 means not.
func connectStatus(t *testing.T, addr, authority, username, password string) int {
	t.Helper()
	cc := dialH2(t, addr, nil)
	body, writer := io.Pipe()
	defer writer.Close()

	header := http.Header{}
	header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	header.Set("padding", naive.RequestPaddingHeader())
	header.Set("padding-type-request", "1, 0")
	header.Set("-connect-authority", authority)

	resp, err := cc.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    mustURL("https://" + authority),
		Host:   authority,
		Header: header,
		Body:   body,
	})
	if err != nil {
		t.Fatalf("CONNECT round trip: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// startNaiveInbound brings up a plaintext h2 naive inbound and returns its
// address. It fails the test if the config is refused, which is the assertion
// that carries every "degrades, not fatal" case below.
func startNaiveInbound(t *testing.T, settings string) string {
	t.Helper()
	port := tcpserver.PickPort()
	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(port)+`,
			"protocol": "naive",
			"settings": `+settings+`
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)
	time.Sleep(300 * time.Millisecond)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// TestBasicUsernameAuth pins the credential semantics: an account with a
// username authenticates under it and no longer under its email, and an account
// without one keeps authenticating under its email exactly as it did before the
// field existed.
func TestBasicUsernameAuth(t *testing.T) {
	target := targetServer(t)
	addr := startNaiveInbound(t, settingsWithClients(
		testClient{Email: "alice@example.com", Username: "alice-vpn", Password: "hunter2"},
		testClient{Email: "bob@example.com", Password: "secret"},
	))
	authority := target.Listener.Addr().String()

	cases := []struct {
		name     string
		username string
		password string
		want     int
	}{
		{"username authenticates", "alice-vpn", "hunter2", http.StatusOK},
		{"username with the wrong password is refused", "alice-vpn", "nope", http.StatusProxyAuthRequired},
		{"the email of a client that has a username no longer authenticates", "alice@example.com", "hunter2", http.StatusProxyAuthRequired},
		{"a client with no username still authenticates by email", "bob@example.com", "secret", http.StatusOK},
		{"email with the wrong password is refused", "bob@example.com", "nope", http.StatusProxyAuthRequired},
		{"one client's username with another's password is refused", "alice-vpn", "secret", http.StatusProxyAuthRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectStatus(t, addr, authority, tc.username, tc.password); got != tc.want {
				t.Fatalf("CONNECT as %q returned %d, want %d", tc.username, got, tc.want)
			}
		})
	}
}

// TestDuplicateUsernameDegrades is the outage guard. Two clients answering to
// one Basic username must cost exactly those clients, never the config: an
// error out of Build makes Xray refuse every inbound on the box.
func TestDuplicateUsernameDegrades(t *testing.T) {
	target := targetServer(t)
	addr := startNaiveInbound(t, settingsWithClients(
		testClient{Email: "first@example.com", Username: "shared", Password: "first-pass"},
		testClient{Email: "second@example.com", Username: "shared", Password: "second-pass"},
		testClient{Email: "carol@example.com", Username: "carol-vpn", Password: "carol-pass"},
	))
	authority := target.Listener.Addr().String()

	// Reaching here at all proves the config loaded. The unrelated account must
	// be untouched by its neighbours' collision.
	if got := connectStatus(t, addr, authority, "carol-vpn", "carol-pass"); got != http.StatusOK {
		t.Fatalf("the unrelated client returned %d, want 200: a duplicate username must not cost other accounts", got)
	}
	if got := connectStatus(t, addr, authority, "shared", "first-pass"); got != http.StatusOK {
		t.Fatalf("the first claimant of a duplicate username returned %d, want 200", got)
	}
	if got := connectStatus(t, addr, authority, "shared", "second-pass"); got != http.StatusProxyAuthRequired {
		t.Fatalf("the second claimant of a duplicate username returned %d, want 407: it must be dropped", got)
	}
}

// TestColonInUsernameDegrades covers the other skip case. A colon cannot be
// expressed in HTTP Basic, so the account is unusable either way; what matters
// is that it is dropped rather than taking the config down with it.
func TestColonInUsernameDegrades(t *testing.T) {
	target := targetServer(t)
	addr := startNaiveInbound(t, settingsWithClients(
		testClient{Email: "bad@example.com", Username: "has:colon", Password: "bad-pass"},
		testClient{Email: "good@example.com", Username: "good-vpn", Password: "good-pass"},
	))
	authority := target.Listener.Addr().String()

	if got := connectStatus(t, addr, authority, "good-vpn", "good-pass"); got != http.StatusOK {
		t.Fatalf("the good client returned %d, want 200: a colon in a neighbour's username must not cost it", got)
	}
	// "has:colon" splits into user "has" and password "colon", and the dropped
	// account cannot be reached under any spelling.
	for _, username := range []string{"has:colon", "has", "bad@example.com"} {
		if got := connectStatus(t, addr, authority, username, "bad-pass"); got != http.StatusProxyAuthRequired {
			t.Fatalf("CONNECT as %q returned %d, want 407: the client must have been dropped", username, got)
		}
	}
}

// TestClientWithNoCredentialIdentityDegrades: a client with neither a username
// nor an email has no Basic username at all. Same rule, drop it and keep going.
func TestClientWithNoCredentialIdentityDegrades(t *testing.T) {
	target := targetServer(t)
	addr := startNaiveInbound(t, settingsWithClients(
		testClient{Password: "orphan-pass"},
		testClient{Email: "dave@example.com", Password: "dave-pass"},
	))
	authority := target.Listener.Addr().String()

	if got := connectStatus(t, addr, authority, "dave@example.com", "dave-pass"); got != http.StatusOK {
		t.Fatalf("the good client returned %d, want 200", got)
	}
	if got := connectStatus(t, addr, authority, "", "orphan-pass"); got != http.StatusProxyAuthRequired {
		t.Fatalf("a client with no username and no email returned %d, want 407", got)
	}
}

// TestOutboundSendsUsername proves the outbound puts the username on the wire.
// The two sides deliberately disagree about the email, so an outbound that
// still sent the email would fail to authenticate.
func TestOutboundSendsUsername(t *testing.T) {
	target := targetServer(t)
	serverPort := tcpserver.PickPort()
	clientPort := tcpserver.PickPort()

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(serverPort)+`,
			"protocol": "naive",
			"settings": `+settingsWithClients(testClient{
		Email:    "server-side@example.com",
		Username: "shared-username",
		Password: "shared-pass",
	})+`
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(clientPort)+`,
			"protocol": "http",
			"settings": {}
		}],
		"outbounds": [{
			"protocol": "naive",
			"settings": {
				"address": "127.0.0.1",
				"port": `+fmt.Sprint(serverPort)+`,
				"email": "client-side@example.com",
				"username": "shared-username",
				"password": "shared-pass",
				"network": "tcp"
			}
		}]
	}`)
	time.Sleep(500 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL(fmt.Sprintf("http://127.0.0.1:%d", clientPort))),
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request through the naive outbound: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "tunnelled ok" {
		t.Fatalf("body %q, want the target's response: the outbound did not send the username", b)
	}
}

func naiveUser(email, username, password string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email:   email,
		Account: &naive.MemoryAccount{Username: username, Password: password},
	}
}

// TestValidatorIndexing covers the two indexes directly, including the one the
// UserManager remove path needs.
func TestValidatorIndexing(t *testing.T) {
	v := naive.NewValidator()
	withUsername := naiveUser("alice@example.com", "alice-vpn", "hunter2")
	byEmailOnly := naiveUser("bob@example.com", "", "secret")
	for _, u := range []*protocol.MemoryUser{withUsername, byEmailOnly} {
		if err := v.Add(u); err != nil {
			t.Fatalf("Add(%s): %v", u.Email, err)
		}
	}

	if got := v.Get("alice-vpn", "hunter2"); got != withUsername {
		t.Fatal("Get by username did not return the user")
	}
	if got := v.Get("alice@example.com", "hunter2"); got != nil {
		t.Fatal("the email of a user that has a username must not authenticate")
	}
	if got := v.Get("bob@example.com", "secret"); got != byEmailOnly {
		t.Fatal("a user with no username must still authenticate by email")
	}
	if got := v.Get("alice-vpn", "wrong"); got != nil {
		t.Fatal("the wrong password must not authenticate")
	}
	// The UserManager removes by email, so both users must be reachable that
	// way whichever name they authenticate under.
	if got := v.GetByEmail("alice@example.com"); got != withUsername {
		t.Fatal("GetByEmail must find a user that authenticates by username")
	}
	if got := v.GetByEmail("bob@example.com"); got != byEmailOnly {
		t.Fatal("GetByEmail must find a user that authenticates by email")
	}
	if v.GetCount() != 2 {
		t.Fatalf("GetCount = %d, want 2", v.GetCount())
	}

	// Del must clear both indexes, or a removed account keeps authenticating.
	if err := v.Del("alice@example.com"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if got := v.Get("alice-vpn", "hunter2"); got != nil {
		t.Fatal("a deleted user still authenticates: Del left the username index behind")
	}
	if got := v.GetByEmail("alice@example.com"); got != nil {
		t.Fatal("a deleted user is still in the email index")
	}
	if v.GetCount() != 1 {
		t.Fatalf("GetCount after Del = %d, want 1", v.GetCount())
	}
}

func TestValidatorAddRejects(t *testing.T) {
	cases := []struct {
		name string
		user *protocol.MemoryUser
	}{
		{"a colon in the username", naiveUser("x@example.com", "has:colon", "pass")},
		{"neither a username nor an email", naiveUser("", "", "pass")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := naive.NewValidator()
			if err := v.Add(tc.user); err == nil {
				t.Fatal("Add accepted the account, want an error for the hot-add caller")
			}
			if v.GetCount() != 0 {
				t.Fatalf("GetCount = %d, want 0: the rejected account was still indexed", v.GetCount())
			}
		})
	}

	t.Run("a duplicate Basic username", func(t *testing.T) {
		v := naive.NewValidator()
		first := naiveUser("first@example.com", "shared", "first-pass")
		if err := v.Add(first); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := v.Add(naiveUser("second@example.com", "shared", "second-pass")); err == nil {
			t.Fatal("Add accepted a duplicate Basic username")
		}
		if got := v.Get("shared", "first-pass"); got != first {
			t.Fatal("the rejected duplicate displaced the account that was already there")
		}
		if got := v.GetByEmail("second@example.com"); got != nil {
			t.Fatal("the rejected duplicate was left in the email index")
		}
	})

	t.Run("a username colliding with another account's email", func(t *testing.T) {
		v := naive.NewValidator()
		if err := v.Add(naiveUser("alice@example.com", "", "first-pass")); err != nil {
			t.Fatalf("Add: %v", err)
		}
		// The fallback means an email occupies the same namespace as a username.
		if err := v.Add(naiveUser("bob@example.com", "alice@example.com", "second-pass")); err == nil {
			t.Fatal("Add accepted a username that collides with another account's email")
		}
	})
}

// TestBasicUsername pins the fallback that both the inbound and the outbound
// resolve credentials through.
func TestBasicUsername(t *testing.T) {
	cases := []struct {
		name string
		user *protocol.MemoryUser
		want string
	}{
		{"username wins", naiveUser("alice@example.com", "alice-vpn", "p"), "alice-vpn"},
		{"empty username falls back to the email", naiveUser("alice@example.com", "", "p"), "alice@example.com"},
		{"no account at all falls back to the email", &protocol.MemoryUser{Email: "alice@example.com"}, "alice@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := naive.BasicUsername(tc.user); got != tc.want {
				t.Fatalf("BasicUsername = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAccountRoundTrip guards the proto field: a username that does not survive
// AsAccount/ToProto would authenticate in tests and silently fall back to the
// email in a real config, which is loaded through the serialized form.
func TestAccountRoundTrip(t *testing.T) {
	account, err := (&naive.Account{Password: "hunter2", Username: "alice-vpn"}).AsAccount()
	if err != nil {
		t.Fatalf("AsAccount: %v", err)
	}
	memory, ok := account.(*naive.MemoryAccount)
	if !ok {
		t.Fatalf("AsAccount returned %T, want *naive.MemoryAccount", account)
	}
	if memory.Username != "alice-vpn" || memory.Password != "hunter2" {
		t.Fatalf("AsAccount lost a field: %+v", memory)
	}
	back, ok := memory.ToProto().(*naive.Account)
	if !ok {
		t.Fatal("ToProto did not return a *naive.Account")
	}
	if back.Username != "alice-vpn" || back.Password != "hunter2" {
		t.Fatalf("ToProto lost a field: %+v", back)
	}
	if !memory.Equals(&naive.MemoryAccount{Password: "hunter2", Username: "alice-vpn"}) {
		t.Fatal("Equals is false for an identical account")
	}
	if memory.Equals(&naive.MemoryAccount{Password: "hunter2"}) {
		t.Fatal("Equals ignores the username, so two different credentials compare equal")
	}
}

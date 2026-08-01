package naive

import (
	"crypto/subtle"
	gotls "crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// AsAccount implements protocol.AsAccount.
func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{Password: a.Password, Username: a.Username}, nil
}

// MemoryAccount is the in-memory form of a naive client credential.
type MemoryAccount struct {
	Password string
	// Username is the Basic-auth username. Empty means the account email is
	// used instead, which is how every client saved before this field existed
	// still authenticates.
	Username string
}

// Equals implements protocol.Account.Equals.
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Password == account.Password && a.Username == account.Username
	}
	return false
}

// ToProto implements protocol.Account.ToProto.
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Password: a.Password, Username: a.Username}
}

// BasicUsername is the name this account authenticates under, which is the
// account's own username when it has one and the email otherwise. It is
// deliberately NOT the accounting identity: statistics, the speed limiter, the
// IP limiter and online detection all key off MemoryUser.Email, so the two must
// stay separable.
func BasicUsername(u *protocol.MemoryUser) string {
	if account, ok := u.Account.(*MemoryAccount); ok && account.Username != "" {
		return account.Username
	}
	return u.Email
}

// Validator holds the naive accounts of one inbound. naive authenticates with
// `Basic base64(username:password)`, so the primary index is by Basic username;
// byEmail exists because the UserManager removes accounts by email.
type Validator struct {
	mutex   sync.RWMutex
	users   map[string]*protocol.MemoryUser
	byEmail map[string]*protocol.MemoryUser
}

func NewValidator() *Validator {
	return &Validator{
		users:   make(map[string]*protocol.MemoryUser),
		byEmail: make(map[string]*protocol.MemoryUser),
	}
}

// Add registers one account. The errors it returns are meant for the gRPC
// hot-add path, where a rejected account is a failed API call and nothing more.
// Callers that build a whole inbound (NewServer) must log and skip instead, or
// one bad account refuses the entire Xray config.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("naive: not a naive account")
	}
	// HTTP Basic splits the decoded credential on the first colon, so a colon in
	// the username makes the account unauthenticable however the password is
	// spelled. The email is not checked: it has always been usable as the Basic
	// username and rejecting one now would break accounts that work today.
	if strings.Contains(account.Username, ":") {
		return errors.New("naive: username ", account.Username, " contains a colon, which HTTP Basic cannot express")
	}
	key := BasicUsername(u)
	if key == "" {
		return errors.New("naive: user must have a username or an email, one of them is the Basic username")
	}
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if _, ok := v.users[key]; ok {
		return errors.New("naive: Basic username ", key, " already exists")
	}
	// A second account on the same email would overwrite byEmail and leave Del
	// unable to reach one of them, so it is rejected the way it always was.
	if u.Email != "" {
		if _, ok := v.byEmail[u.Email]; ok {
			return errors.New("naive: user ", u.Email, " already exists")
		}
	}
	v.users[key] = u
	if u.Email != "" {
		v.byEmail[u.Email] = u
	}
	return nil
}

func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("naive: email must not be empty")
	}
	v.mutex.Lock()
	defer v.mutex.Unlock()
	u, ok := v.byEmail[email]
	if !ok {
		return errors.New("naive: user ", email, " not found")
	}
	delete(v.byEmail, email)
	delete(v.users, BasicUsername(u))
	return nil
}

// Get returns the user matching a Basic credential pair, or nil.
func (v *Validator) Get(username, password string) *protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	u, ok := v.users[username]
	if !ok {
		return nil
	}
	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(account.Password), []byte(password)) != 1 {
		return nil
	}
	return u
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return v.byEmail[email]
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, u := range v.users {
		users = append(users, u)
	}
	return users
}

func (v *Validator) GetCount() int64 {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return int64(len(v.users))
}

// buildMasquerade turns the masquerade config into the http.Handler that serves
// everything that is not an authenticated CONNECT. Since naiveproxy v147 the
// client itself fetches "/" over the same session and then refetches the
// same-origin subresources it finds, so this handler is load-bearing for the
// camouflage, not decoration.
func buildMasquerade(config *Masquerade) (http.Handler, error) {
	var typ, file, rawURL, content string
	var rewriteHost, insecure bool
	var headers map[string]string
	var statusCode int32
	if config != nil {
		typ, file, rawURL, content = config.Type, config.File, config.Url, config.Content
		rewriteHost, insecure = config.UrlRewriteHost, config.UrlInsecure
		headers, statusCode = config.Headers, config.StatusCode
	}

	switch strings.ToLower(typ) {
	case "", "404":
		return http.NotFoundHandler(), nil
	case "file":
		if file == "" {
			return nil, errors.New("naive: masquerade type file needs a directory")
		}
		return http.FileServer(http.Dir(file)), nil
	case "proxy":
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, errors.New("naive: bad masquerade url").Base(err)
		}
		transport := http.DefaultTransport.(*http.Transport)
		if insecure {
			transport = transport.Clone()
			transport.TLSClientConfig = &gotls.Config{InsecureSkipVerify: true}
		}
		return &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				if !rewriteHost {
					pr.Out.Host = pr.In.Host
				}
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			},
		}, nil
	case "string":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			if statusCode != 0 {
				w.WriteHeader(int(statusCode))
			} else {
				w.WriteHeader(http.StatusOK)
			}
			_, _ = w.Write([]byte(content))
		}), nil
	default:
		return nil, errors.New("naive: unknown masquerade type ", typ)
	}
}

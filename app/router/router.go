package router

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
)

// Router is an implementation of routing.Router.
type Router struct {
	dns dns.Client

	// Published states are immutable. A route keeps one snapshot through DNS
	// resolution and balancer selection while configuration builds independently.
	state atomic.Pointer[routerState]

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	mu         sync.Mutex
}

type routerState struct {
	domainStrategy Config_DomainStrategy
	rules          []*Rule
	balancers      map[string]*Balancer
}

func (r *Router) currentState() *routerState {
	if state := r.state.Load(); state != nil {
		return state
	}
	return &routerState{}
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher
	// Existing startup configurations permit repeated labels (and the final
	// balancing entry wins). Keep that compatibility while live reloads retain
	// their stricter duplicate checks.
	return r.reloadRules(config, false, true)
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	originalCtx := ctx
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	if config == nil {
		return errors.New("routing config is missing")
	}
	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	if c, ok := inst.(*Config); ok {
		return r.ReloadRules(c, shouldAppend)
	}
	return errors.New("AddRule: config type error")
}

// ReloadRules builds the complete candidate before publishing it. A rejected
// replacement or append leaves the running routes, balancers and strategy intact.
func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	return r.reloadRules(config, shouldAppend, false)
}

func (r *Router) reloadRules(config *Config, shouldAppend, initializing bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if config == nil {
		return errors.New("routing config is missing")
	}

	previous := r.currentState()
	next := &routerState{
		domainStrategy: config.DomainStrategy,
		rules:          make([]*Rule, 0, len(config.Rule)),
		balancers:      make(map[string]*Balancer, len(config.BalancingRule)),
	}
	if shouldAppend {
		next.domainStrategy = previous.domainStrategy
		// Never append into a published slice's backing array or mutate its map.
		next.rules = append(next.rules, previous.rules...)
		for tag, balancer := range previous.balancers {
			next.balancers[tag] = balancer
		}
	}
	newRuleStart := len(next.rules)
	published := false
	defer func() {
		if !published {
			closeRuleWebhooks(next.rules[newRuleStart:])
		}
	}()

	for _, rule := range config.BalancingRule {
		if rule == nil {
			return errors.New("balancing rule is missing")
		}
		if _, found := next.balancers[rule.Tag]; found && !initializing {
			return errors.New("duplicate balancer tag")
		}
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(r.ctx)
		next.balancers[rule.Tag] = balancer
	}

	for _, rule := range config.Rule {
		if rule == nil {
			return errors.New("routing rule is missing")
		}
		if !initializing && ruleExists(next.rules, rule.GetRuleTag()) {
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		if btag := rule.GetBalancingTag(); btag != "" {
			balancer, found := next.balancers[btag]
			if !found {
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = balancer
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				return err
			}
			rr.Webhook = notifier
		}
		next.rules = append(next.rules, rr)
	}

	r.state.Store(next)
	published = true
	if !shouldAppend {
		closeRuleWebhooks(previous.rules)
	}
	return nil
}

func ruleExists(rules []*Rule, tag string) bool {
	if tag != "" {
		for _, rule := range rules {
			if rule.RuleTag == tag {
				return true
			}
		}
	}
	return false
}

func (r *Router) RuleExists(tag string) bool {
	return ruleExists(r.currentState().rules, tag)
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tag == "" {
		return errors.New("empty tag name!")
	}
	previous := r.currentState()
	next := &routerState{
		domainStrategy: previous.domainStrategy,
		balancers:      previous.balancers,
		rules:          make([]*Rule, 0, len(previous.rules)),
	}
	var removed []*Rule
	for _, rule := range previous.rules {
		if rule.RuleTag != tag {
			next.rules = append(next.rules, rule)
		} else {
			removed = append(removed, rule)
		}
	}
	r.state.Store(next)
	closeRuleWebhooks(removed)
	return nil
}

// ListRule implements routing.Router
func (r *Router) ListRule() []routing.Route {
	state := r.currentState()
	ruleList := make([]routing.Route, 0, len(state.rules))
	for _, rule := range state.rules {
		ruleList = append(ruleList, &Route{
			outboundTag: rule.Tag,
			ruleTag:     rule.RuleTag,
		})
	}
	return ruleList
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	state := r.currentState()
	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()

	if state.domainStrategy == Config_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	for _, rule := range state.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	if state.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range state.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

func closeRuleWebhooks(rules []*Rule) {
	for _, rule := range rules {
		if rule.Webhook != nil {
			rule.Webhook.Close()
		}
	}
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	closeRuleWebhooks(r.currentState().rules)
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}

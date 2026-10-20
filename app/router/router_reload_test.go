package router

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func reloadTestRule(tag string, network net.Network) *RoutingRule {
	return &RoutingRule{
		RuleTag: tag, TargetTag: &RoutingRule_Tag{Tag: tag},
		Networks: []net.Network{network},
	}
}

func reloadTestContext(network net.Network) routing.Context {
	return &routing_session.Context{Outbound: &session.Outbound{
		Target: net.Destination{Network: network, Address: net.IPAddress([]byte{1, 1, 1, 1}), Port: 443},
	}}
}

func TestRouterInitPreservesLegacyDuplicateLabels(t *testing.T) {
	first := reloadTestRule("legacy-label", net.Network_TCP)
	second := reloadTestRule("legacy-label", net.Network_UDP)
	second.TargetTag = &RoutingRule_Tag{Tag: "legacy-udp"}
	configuration := &Config{
		Rule: []*RoutingRule{first, second},
		BalancingRule: []*BalancingRule{
			{Tag: "legacy-balancer", Strategy: "random"},
			{Tag: "legacy-balancer", Strategy: "roundrobin"},
		},
	}
	r := new(Router)
	if err := r.Init(context.Background(), configuration, nil, nil, nil); err != nil {
		t.Fatalf("previously accepted startup configuration was rejected: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	before := r.currentState()
	if _, ok := before.balancers["legacy-balancer"].strategy.(*RoundRobinStrategy); !ok {
		t.Fatal("startup did not preserve last duplicate balancer wins behavior")
	}
	for network, want := range map[net.Network]string{net.Network_TCP: "legacy-label", net.Network_UDP: "legacy-udp"} {
		route, err := r.PickRoute(reloadTestContext(network))
		if err != nil || route.GetOutboundTag() != want {
			t.Fatalf("startup duplicate label lost route: route=%v err=%v want=%s", route, err, want)
		}
	}
	for name, candidate := range map[string]*Config{
		"duplicate balancer": configuration,
		"duplicate rule":     {Rule: []*RoutingRule{first, second}},
	} {
		if err := r.ReloadRules(candidate, false); err == nil {
			t.Fatalf("live replacement with %s succeeded", name)
		}
		if r.currentState() != before {
			t.Fatalf("rejected %s changed live startup state", name)
		}
	}
}

func TestReloadRulesFailureKeepsLiveConfiguration(t *testing.T) {
	cases := map[string]*Config{
		"missing config":  nil,
		"empty condition": {Rule: []*RoutingRule{{RuleTag: "empty"}}},
		"nil rule":        {Rule: []*RoutingRule{nil}},
		"nil balancer":    {BalancingRule: []*BalancingRule{nil}},
		"invalid pattern": {Rule: []*RoutingRule{{Attributes: map[string]string{"test": "["}}}},
		"missing balancer": {Rule: []*RoutingRule{{
			Networks:  []net.Network{net.Network_TCP},
			TargetTag: &RoutingRule_BalancingTag{BalancingTag: "missing"},
		}}},
		"duplicate rule": {Rule: []*RoutingRule{
			reloadTestRule("duplicate", net.Network_TCP), reloadTestRule("duplicate", net.Network_UDP),
		}},
		"invalid balancer after valid balancer": {BalancingRule: []*BalancingRule{
			{Tag: "candidate"}, {Tag: "invalid", Strategy: "unsupported"},
		}},
		"duplicate balancer": {BalancingRule: []*BalancingRule{{Tag: "duplicate"}, {Tag: "duplicate"}}},
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			oldRule := reloadTestRule("live", net.Network_TCP)
			oldRule.Webhook = &WebhookConfig{Url: "http://127.0.0.1:1/", Deduplication: 1}
			r := new(Router)
			if err := r.Init(context.Background(), &Config{
				DomainStrategy: Config_IpOnDemand, Rule: []*RoutingRule{oldRule},
				BalancingRule: []*BalancingRule{{Tag: "live-balancer"}},
			}, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			before := r.currentState()
			if candidate != nil {
				candidate.DomainStrategy = Config_IpIfNonMatch
			}
			if err := r.ReloadRules(candidate, false); err == nil {
				t.Fatal("invalid replacement succeeded")
			}
			if r.currentState() != before {
				t.Fatal("failed replacement published a different configuration")
			}
			select {
			case <-before.rules[0].Webhook.done:
				t.Fatal("failed replacement closed the live webhook")
			default:
			}
			rule, _, err := r.pickRouteInternal(reloadTestContext(net.Network_TCP))
			if err != nil || rule.Tag != "live" {
				t.Fatalf("live route lost after failed replacement: rule=%v err=%v", rule, err)
			}
		})
	}
}

func TestReloadRulesAppendPreservesPriorityAndRollsBack(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule:           []*RoutingRule{reloadTestRule("live", net.Network_TCP)},
		BalancingRule:  []*BalancingRule{{Tag: "live-balancer"}},
	}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	before := r.currentState()
	if err := r.ReloadRules(&Config{
		BalancingRule: []*BalancingRule{{Tag: "must-not-leak"}},
		Rule:          []*RoutingRule{reloadTestRule("live", net.Network_UDP)},
	}, true); err == nil {
		t.Fatal("append with duplicate rule tag succeeded")
	}
	if r.currentState() != before {
		t.Fatal("failed append changed active rules or leaked a new balancer")
	}
	if err := r.ReloadRules(&Config{Rule: []*RoutingRule{
		reloadTestRule("later-tcp", net.Network_TCP), reloadTestRule("new-udp", net.Network_UDP),
	}}, true); err != nil {
		t.Fatal(err)
	}
	if r.currentState().domainStrategy != Config_IpIfNonMatch || len(before.rules) != 1 {
		t.Fatal("append changed domain strategy or modified the prior snapshot")
	}
	for network, want := range map[net.Network]string{net.Network_TCP: "live", net.Network_UDP: "new-udp"} {
		route, err := r.PickRoute(reloadTestContext(network))
		if err != nil || route.GetOutboundTag() != want {
			t.Fatalf("route for %v: route=%v err=%v want=%s", network, route, err, want)
		}
	}
	if err := r.RemoveRule("new-udp"); err != nil {
		t.Fatal(err)
	}
	if r.RuleExists("new-udp") || !r.RuleExists("live") {
		t.Fatal("remove did not preserve the other active rules")
	}
	if err := r.ReloadRules(&Config{
		DomainStrategy: Config_IpOnDemand,
		Rule:           []*RoutingRule{reloadTestRule("replacement", net.Network_TCP)},
	}, false); err != nil {
		t.Fatal(err)
	}
	if state := r.currentState(); state.domainStrategy != Config_IpOnDemand || len(state.balancers) != 0 || r.RuleExists("live") {
		t.Fatal("successful replacement retained stale rules, balancers or strategy")
	}
}

// A route in progress must finish against the old snapshot, while publication
// does not wait for that connection's DNS lookup or condition evaluation.
func TestReloadRulesDoesNotWaitForInFlightRoute(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	r := new(Router)
	r.state.Store(&routerState{rules: []*Rule{{
		Tag: "old", RuleTag: "old", Condition: reloadBlockingCondition{entered: entered, release: release},
	}}})
	result := make(chan error, 1)
	go func() {
		route, err := r.PickRoute(reloadTestContext(net.Network_TCP))
		if err == nil && route.GetOutboundTag() != "old" {
			err = fmt.Errorf("in-flight route switched configuration: %s", route.GetOutboundTag())
		}
		result <- err
	}()
	<-entered
	releaseRoute := sync.OnceFunc(func() { close(release) })
	defer releaseRoute()
	reloaded := make(chan error, 1)
	go func() {
		reloaded <- r.ReloadRules(&Config{Rule: []*RoutingRule{reloadTestRule("new", net.Network_TCP)}}, false)
	}()
	select {
	case err := <-reloaded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reload waited for an unrelated in-flight route")
	}
	newRoute, err := r.PickRoute(reloadTestContext(net.Network_TCP))
	if err != nil || newRoute.GetOutboundTag() != "new" {
		t.Fatalf("new route did not use published configuration: route=%v err=%v", newRoute, err)
	}
	releaseRoute()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

type reloadBlockingCondition struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (c reloadBlockingCondition) Apply(routing.Context) bool {
	close(c.entered)
	<-c.release
	return true
}

func TestReloadRulesConcurrentRouting(t *testing.T) {
	r := new(Router)
	configuration := func(tag string) *Config {
		return &Config{Rule: []*RoutingRule{reloadTestRule(tag, net.Network_TCP)},
			BalancingRule: []*BalancingRule{{Tag: "balance"}}}
	}
	if err := r.Init(context.Background(), configuration("a"), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 500 {
				route, err := r.PickRoute(reloadTestContext(net.Network_TCP))
				if err != nil {
					t.Errorf("routing failed during replacement: %v", err)
					return
				}
				if tag := route.GetOutboundTag(); tag != "a" && tag != "b" {
					t.Errorf("partial routing state observed: %q", tag)
					return
				}
				r.ListRule()
				r.RuleExists("a")
				if err := r.SetOverrideTarget("balance", "override"); err != nil {
					t.Error(err)
				}
				r.GetOverrideTarget("balance")
				r.OverrideBalancer("balance", "override")
			}
		})
	}
	for i := range 200 {
		tag := "a"
		if i%2 == 0 {
			tag = "b"
		}
		if err := r.ReloadRules(configuration(tag), false); err != nil {
			t.Fatal(err)
		}
		if err := r.ReloadRules(&Config{Rule: []*RoutingRule{reloadTestRule("unused", net.Network_UDP)}}, true); err != nil {
			t.Fatal(err)
		}
		if err := r.RemoveRule("unused"); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}

func TestRetiredWebhookConcurrentFireAndClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	for range 20 {
		notifier, err := NewWebhookNotifier(&WebhookConfig{Url: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		for range 4 {
			workers.Go(func() {
				for range 20 {
					notifier.Fire(reloadTestContext(net.Network_TCP), "direct")
				}
			})
		}
		if err := notifier.Close(); err != nil {
			t.Fatal(err)
		}
		workers.Wait()
		notifier.Fire(reloadTestContext(net.Network_TCP), "direct")
	}
}

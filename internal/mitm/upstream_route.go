package mitm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/egress"
)

// upstreamRoute is the per-request answer to "how do I reach this upstream?".
// The zero-ish value returned when nothing is configured carries the proxy's
// baseline transport, which is exactly the behaviour that existed before
// egress proxies did.
type upstreamRoute struct {
	transport *http.Transport
	// tunnel is non-nil only when the route goes through a proxy, and only
	// WebSocket upgrades use it: a hijacked connection needs the raw
	// tunneled net.Conn rather than anything net/http can RoundTrip.
	tunnel  egress.TunnelDialer
	profile *brokercore.UpstreamProxy
}

// routeFor resolves the egress route for one brokered request. host is the
// upstream address in host:port form and is used for NO_PROXY matching.
//
// Errors are returned only when a profile exists, applies to this request,
// cannot be turned into a dialler, and is not configured to fail open. Every
// other outcome (no resolver, no profile, no_proxy hit, resolver failure)
// degrades to a direct connection so availability never depends on the
// configuration being perfect.
func (p *Proxy) routeFor(ctx context.Context, vaultID, serviceName, host string) (upstreamRoute, error) {
	direct := upstreamRoute{transport: p.upstream}
	if p.upstreamRes == nil || p.egress == nil {
		return direct, nil
	}

	profile, err := p.upstreamRes.ResolveUpstreamProxy(ctx, vaultID, serviceName)
	if err != nil {
		p.logger.Warn("upstream proxy resolution failed; dialling upstream directly",
			slog.String("vault_id", vaultID),
			slog.String("service", serviceName),
			slog.String("error", err.Error()))
		return direct, nil
	}
	if profile == nil {
		return direct, nil
	}
	if egress.Bypass(profile.NoProxy, host) {
		p.logger.Debug("request bypasses upstream proxy (no_proxy)",
			slog.String("host", host),
			slog.String("profile", profile.Name))
		return direct, nil
	}

	transport, transportErr := p.egress.Transport(profile)
	tunnel, tunnelErr := p.egress.Tunnel(profile)
	if transportErr != nil || tunnelErr != nil {
		buildErr := transportErr
		if buildErr == nil {
			buildErr = tunnelErr
		}
		p.logger.Warn("upstream proxy profile is unusable",
			slog.String("profile", profile.Name),
			slog.String("scheme", profile.Scheme),
			slog.String("error", buildErr.Error()))
		if profile.FailureMode() == brokercore.UpstreamProxyFailOpen {
			return direct, nil
		}
		return upstreamRoute{}, fmt.Errorf("upstream proxy %q is unusable: %w", profile.Name, buildErr)
	}

	p.logger.Debug("routing request through upstream proxy",
		slog.String("host", host),
		slog.String("profile", profile.Name),
		slog.String("scheme", profile.Scheme))

	return upstreamRoute{transport: transport, tunnel: tunnel, profile: profile}, nil
}

// failOpenReplayBytes caps how much request body is held in memory purely so a
// fail_open profile can replay the request directly after a failed proxy hop.
// Requests above this keep the "honour the proxy or fail" behaviour: a half-
// sent replay is worse than an honest 502.
const failOpenReplayBytes = 8 << 20

// roundTrip sends req through route, honouring the profile's failure policy.
//
// Only failures tagged as reaching *the proxy itself* are eligible for the
// fail_open fallback; a target-side error is returned untouched. Without that
// distinction, any upstream problem (TLS mismatch, DNS failure at the target)
// would silently convert into a policy bypass — the one thing an operator
// trusting an egress proxy must never get.
func (p *Proxy) roundTrip(outReq *http.Request, route upstreamRoute, target string) (*http.Response, error) {
	if route.profile == nil || route.profile.FailureMode() != brokercore.UpstreamProxyFailOpen {
		return route.transport.RoundTrip(outReq)
	}

	replay, replayable := p.replayableBody(outReq)
	resp, err := route.transport.RoundTrip(outReq)
	if err == nil || !errors.Is(err, egress.ErrProxyUnreachable) {
		return resp, err
	}
	if !replayable {
		return resp, err
	}
	if replay != nil {
		outReq.Body = replay()
	}
	p.logger.Warn("egress proxy unreachable; dialling directly under fail_open",
		slog.String("profile", route.profile.Name),
		slog.String("target", target),
		slog.String("host", route.profile.Host),
		slog.String("error", err.Error()))
	return p.upstream.RoundTrip(outReq)
}

// replayableBody reports whether outReq's body can be replayed for a second
// attempt, and returns the factory that produces it. Absent bodies are
// trivially replayable; large or chunked ones are not.
func (p *Proxy) replayableBody(outReq *http.Request) (func() io.ReadCloser, bool) {
	if outReq.Body == nil {
		return nil, true
	}
	if outReq.GetBody != nil {
		return func() io.ReadCloser {
			body, err := outReq.GetBody()
			if err != nil {
				return nil
			}
			return body
		}, true
	}
	if outReq.ContentLength < 0 || outReq.ContentLength > failOpenReplayBytes {
		p.logger.Debug("request too large to replay; fail_open fallback unavailable",
			slog.Int64("content_length", outReq.ContentLength))
		return nil, false
	}
	data, err := io.ReadAll(outReq.Body)
	if err != nil {
		p.logger.Debug("could not buffer request body for replay",
			slog.String("error", err.Error()))
		return nil, false
	}
	_ = outReq.Body.Close()
	outReq.Body = io.NopCloser(bytes.NewReader(data))
	return func() io.ReadCloser { return io.NopCloser(bytes.NewReader(data)) }, true
}

// dial opens the next hop for a hijacked connection (WebSocket upgrades),
// applying the same fail_open policy as roundTrip: a proxy that cannot be
// reached is swapped for the baseline direct dial, everything else is
// returned as-is.
func (p *Proxy) dial(ctx context.Context, addr string, route upstreamRoute, transport *http.Transport) (net.Conn, error) {
	dialCtx := transport.DialContext
	if route.tunnel != nil {
		dialCtx = route.tunnel
	}
	if dialCtx == nil {
		dialer := &net.Dialer{}
		dialCtx = dialer.DialContext
	}

	conn, err := dialCtx(ctx, "tcp", addr)
	if err == nil || route.tunnel == nil || route.profile == nil {
		return conn, err
	}
	if route.profile.FailureMode() != brokercore.UpstreamProxyFailOpen ||
		!errors.Is(err, egress.ErrProxyUnreachable) {
		return conn, err
	}

	p.logger.Warn("egress proxy unreachable; dialling upstream directly under fail_open",
		slog.String("profile", route.profile.Name),
		slog.String("target", addr),
		slog.String("host", route.profile.Host),
		slog.String("error", err.Error()))
	if transport.DialContext != nil {
		return transport.DialContext(ctx, "tcp", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

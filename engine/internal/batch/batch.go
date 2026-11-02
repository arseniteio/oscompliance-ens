package batch

import (
	"context"
	"sync"
)

const Size = 500

type Plan struct {
	mu      sync.Mutex
	ids     []string
	order   map[string]int
	entries map[string]*entry
}

type entry struct {
	mu     sync.Mutex
	loaded bool
	chunk  int
	data   any
	err    error
}

func (p *Plan) Set(agentIDs []string) {

	p.mu.Lock()
	defer p.mu.Unlock()

	p.ids = append([]string(nil), agentIDs...)
	p.order = make(map[string]int, len(agentIDs))
	for i, id := range agentIDs {
		p.order[id] = i
	}
	p.entries = map[string]*entry{}
}

func (p *Plan) Has(agentID string) bool {

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.order == nil {
		return true
	}
	_, ok := p.order[agentID]
	return ok
}

func (p *Plan) chunkOf(agentID string) ([]string, int) {

	p.mu.Lock()
	defer p.mu.Unlock()

	i, ok := p.order[agentID]
	if !ok {
		return nil, 0
	}

	c := i / Size
	return p.ids[c*Size : min((c+1)*Size, len(p.ids))], c
}

func (p *Plan) entry(key string) *entry {

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.entries == nil {
		p.entries = map[string]*entry{}
	}
	e, ok := p.entries[key]
	if !ok {
		e = &entry{}
		p.entries[key] = e
	}
	return e
}

type scopeKey struct{}

func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope)
}

func ScopeOf(ctx context.Context) string {
	scope, _ := ctx.Value(scopeKey{}).(string)
	return scope
}

func scoped(ctx context.Context, key string) string {
	return ScopeOf(ctx) + "|" + key
}

func Once[R any](ctx context.Context, p *Plan, key string, fetch func(ctx context.Context) (R, error)) (R, error) {

	e := p.entry("once|" + key)
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.loaded {
		r, err := fetch(ctx)
		e.loaded, e.data, e.err = true, r, err
	}

	var zero R
	if e.err != nil {
		return zero, e.err
	}
	return e.data.(R), nil
}

func Get[R any](ctx context.Context, p *Plan, key, agentID string, fetch func(ctx context.Context, ids []string) (map[string]R, error)) (R, error) {

	ids, chunk := p.chunkOf(agentID)
	if ids == nil {
		m, err := fetch(ctx, []string{agentID})
		return m[agentID], err
	}

	e := p.entry(scoped(ctx, key))
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.loaded || e.chunk != chunk {
		m, err := fetch(ctx, ids)
		e.loaded, e.chunk, e.data, e.err = true, chunk, m, err
	}

	var zero R
	if e.err != nil {
		return zero, e.err
	}
	return e.data.(map[string]R)[agentID], nil
}

func Update[R any](ctx context.Context, p *Plan, key, agentID string, fn func(R) R) {

	ids, chunk := p.chunkOf(agentID)
	if ids == nil {
		return
	}

	e := p.entry(scoped(ctx, key))
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.loaded || e.chunk != chunk || e.err != nil {
		return
	}
	m := e.data.(map[string]R)
	m[agentID] = fn(m[agentID])
}

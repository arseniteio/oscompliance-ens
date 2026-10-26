// Package batch serves per-agent reads from reads of many agents at once.
//
// Controls judge one agent at a time, but a query per agent and per kind of
// read does not scale to a large fleet. With a plan (the agents of the pass,
// in the order they are judged), the first read of a kind for an agent
// fetches its whole chunk of Size agents, and the next agents of the chunk
// are answered from memory. Only the newest chunk of each kind is kept, so
// memory stays bounded whatever the fleet size. Readers that walk the agents
// side by side (one control each) keep their chunks apart with WithScope.
package batch

import (
	"context"
	"sync"
)

// Size is how many agents one fetch covers.
const Size = 500

// Plan is the agents of one pass and the chunks read so far. The zero value
// has no agents: every read fetches one agent.
type Plan struct {
	mu      sync.Mutex
	ids     []string
	order   map[string]int
	entries map[string]*entry
}

// entry is the newest chunk fetched for one kind of read.
type entry struct {
	mu     sync.Mutex
	loaded bool
	chunk  int
	data   any // map[string]R by agent ID
	err    error
}

// Set starts a pass with the agents in the order they will be read, and
// forgets every chunk of the previous pass.
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

// chunkOf returns the agents of agentID's chunk and its number, or nil when
// the agent is not in the plan.
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

// WithScope returns a context whose reads keep their own chunks: two
// controls walking the agents at once do not evict each other's chunk.
func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope)
}

func scoped(ctx context.Context, key string) string {
	scope, _ := ctx.Value(scopeKey{}).(string)
	return scope + "|" + key
}

// Once returns what fetch reads for key, read once per pass and shared by
// every reader: a read of the whole fleet that several controls need.
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

// Get answers one agent's read of kind key from the chunk of the agent,
// fetching the chunk when it is not the one in memory. fetch gets the agent
// IDs and returns the result of each; an agent missing from it has the zero
// result. A failed fetch fails every agent of the chunk.
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

// Update changes one agent's result of kind key in memory, when its chunk is
// the one held: a write later reads of the same pass must see.
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

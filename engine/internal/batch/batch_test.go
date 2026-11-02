package batch

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestGetFetchesEachChunkOnce(t *testing.T) {

	var ids []string
	for i := range Size + 10 {
		ids = append(ids, fmt.Sprint(i))
	}

	var p Plan
	p.Set(ids)

	fetches := 0
	fetch := func(_ context.Context, chunk []string) (map[string]int, error) {
		fetches++
		out := map[string]int{}
		for _, id := range chunk {
			out[id] = len(chunk)
		}
		return out, nil
	}

	for _, id := range ids {
		n, err := Get(context.Background(), &p, "k", id, fetch)
		if err != nil {
			t.Fatal(err)
		}
		want := Size
		if id >= fmt.Sprint(Size) && len(id) == len(fmt.Sprint(Size)) {
			want = 10
		}
		if n != want {
			t.Fatalf("agent %s: chunk of %d, want %d", id, n, want)
		}
	}

	if fetches != 2 {
		t.Fatalf("%d fetches, want 2", fetches)
	}
}

func TestGetWithoutPlanFetchesOneAgent(t *testing.T) {

	var p Plan
	got, err := Get(context.Background(), &p, "k", "007", func(_ context.Context, ids []string) (map[string][]string, error) {
		return map[string][]string{ids[0]: ids}, nil
	})
	if err != nil || len(got) != 1 || got[0] != "007" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestGetFailsTheChunk(t *testing.T) {

	var p Plan
	p.Set([]string{"001", "002"})

	fetches := 0
	fetch := func(context.Context, []string) (map[string]int, error) {
		fetches++
		return nil, errors.New("down")
	}

	for _, id := range []string{"001", "002"} {
		if _, err := Get(context.Background(), &p, "k", id, fetch); err == nil {
			t.Fatalf("agent %s: no error", id)
		}
	}
	if fetches != 1 {
		t.Fatalf("%d fetches, want 1", fetches)
	}
}

func TestUpdateChangesTheChunkHeld(t *testing.T) {

	var p Plan
	p.Set([]string{"001", "002"})

	fetch := func(_ context.Context, ids []string) (map[string]int, error) {
		return map[string]int{"001": 1, "002": 2}, nil
	}

	if _, err := Get(context.Background(), &p, "k", "001", fetch); err != nil {
		t.Fatal(err)
	}
	Update(context.Background(), &p, "k", "002", func(n int) int { return n + 40 })

	if n, _ := Get(context.Background(), &p, "k", "002", fetch); n != 42 {
		t.Fatalf("got %d, want 42", n)
	}

	p.Set([]string{"001", "002"})
	if n, _ := Get(context.Background(), &p, "k", "002", fetch); n != 2 {
		t.Fatalf("new pass: got %d, want 2", n)
	}
}

func TestScopesKeepTheirChunks(t *testing.T) {

	var ids []string
	for i := range 2 * Size {
		ids = append(ids, fmt.Sprintf("%04d", i))
	}
	var p Plan
	p.Set(ids)

	fetches := 0
	fetch := func(_ context.Context, chunk []string) (map[string]int, error) {
		fetches++
		return map[string]int{}, nil
	}

	a, b := WithScope(context.Background(), "a"), WithScope(context.Background(), "b")
	for i := range Size {
		Get(a, &p, "k", ids[Size+i], fetch)
		Get(b, &p, "k", ids[i], fetch)
	}
	if fetches != 2 {
		t.Fatalf("%d fetches, want 2", fetches)
	}
}

func TestOnceFetchesOncePerPass(t *testing.T) {

	var p Plan
	p.Set(nil)
	fetches := 0
	fetch := func(context.Context) (int, error) { fetches++; return 7, nil }

	for range 3 {
		if n, _ := Once(context.Background(), &p, "k", fetch); n != 7 {
			t.Fatalf("got %d", n)
		}
	}
	p.Set(nil)
	Once(context.Background(), &p, "k", fetch)
	if fetches != 2 {
		t.Fatalf("%d fetches, want 2", fetches)
	}
}

func TestPlanHas(t *testing.T) {

	var p Plan
	if !p.Has("001") {
		t.Error("before a plan every machine is judged")
	}

	p.Set([]string{"001"})
	if !p.Has("001") || p.Has("002") {
		t.Error("after a plan only its machines are")
	}
}

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// External-user service events: lines of a service's authentication log in
// the op.acc.5 contract, read by a Wazuh localfile labelled
// oscompliance_service and indexed by rule 119003. Times are the alert's:
// when Wazuh received the line, which the agent sends as it is written.

// ServiceRule is the Wazuh rule of the service events (catalog/wazuh).
const ServiceRule = "119003"

// compositePage is the number of buckets per composite aggregation page.
const compositePage = 1000

// ServiceEvent is one decoded contract line.
type ServiceEvent struct {
	Time           time.Time
	Service        string
	Tipo           string
	Usuario        string
	Origen         string
	Resultado      string
	Factores       []string
	Mensaje        string
	Emisor         string
	Revocacion     string
	Modo           string
	Referencia     string
	Bloqueo        string
	MaxIntentos    string
	Reactivacion   string
	LongitudMinima string
	Complejidad    string
}

func serviceFilter(ids []string, since time.Time, extra ...any) []any {

	filter := []any{
		map[string]any{"term": map[string]any{"rule.id": ServiceRule}},
		agentFilter(ids),
	}

	if !since.IsZero() {
		filter = append(filter, map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}})
	}

	return append(filter, extra...)
}

func termFilter(field string, values ...string) any {
	if len(values) == 1 {
		return map[string]any{"term": map[string]any{field: values[0]}}
	}
	return map[string]any{"terms": map[string]any{field: values}}
}

// ServiceEvents returns the events of one agent of the given types since
// the given time (zero: as far back as the index goes), oldest first. match
// keeps only events whose data field has one of the values ("usuario":
// accounts). Meant for the rare types (notices, disablements, policy) and
// for the few accounts or origins whose failures need an exact count.
func (s *Source) ServiceEvents(ctx context.Context, agentID string, since time.Time, tipos []string, match map[string][]string) ([]ServiceEvent, error) {

	fetch := func(ctx context.Context, ids []string) (map[string][]ServiceEvent, error) {
		return s.serviceEvents(ctx, ids, since, tipos, match)
	}

	// The values to match are this agent's own: no batch.
	if len(match) > 0 {
		m, err := fetch(ctx, []string{agentID})
		return m[agentID], err
	}

	return batched(ctx, s, fmt.Sprint("events|", sinceKey(since), tipos), agentID, fetch)
}

func (s *Source) serviceEvents(ctx context.Context, ids []string, since time.Time, tipos []string, match map[string][]string) (map[string][]ServiceEvent, error) {

	extra := []any{termFilter("data.tipo", tipos...)}
	for field, values := range match {
		if len(values) > 0 {
			extra = append(extra, termFilter("data."+field, values...))
		}
	}

	out := map[string][]ServiceEvent{}

	err := s.page(ctx, serviceFilter(ids, since, extra...), func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Agent     struct {
				ID string `json:"id"`
			} `json:"agent"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		var d struct {
			Service        string `json:"oscompliance_service"`
			Tipo           string `json:"tipo"`
			Usuario        string `json:"usuario"`
			Origen         string `json:"origen"`
			Resultado      string `json:"resultado"`
			Factores       any    `json:"factores"`
			Mensaje        string `json:"mensaje"`
			Emisor         string `json:"certificado_emisor"`
			Revocacion     string `json:"revocacion"`
			Modo           string `json:"modo"`
			Referencia     string `json:"referencia"`
			Bloqueo        string `json:"bloqueo"`
			MaxIntentos    any    `json:"max_intentos"`
			Reactivacion   string `json:"reactivacion"`
			LongitudMinima any    `json:"longitud_minima"`
			Complejidad    string `json:"complejidad"`
		}
		if err := json.Unmarshal(a.Data, &d); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		out[a.Agent.ID] = append(out[a.Agent.ID], ServiceEvent{
			Time: ts, Service: d.Service, Tipo: d.Tipo, Usuario: d.Usuario, Origen: d.Origen, Resultado: d.Resultado,
			Factores: stringList(d.Factores), Mensaje: d.Mensaje, Emisor: d.Emisor, Revocacion: d.Revocacion,
			Modo: d.Modo, Referencia: d.Referencia, Bloqueo: d.Bloqueo, MaxIntentos: scalar(d.MaxIntentos),
			Reactivacion: d.Reactivacion, LongitudMinima: scalar(d.LongitudMinima), Complejidad: d.Complejidad,
		})
		return nil
	})

	return out, err
}

// stringList reads a JSON array of strings, or a single string.
func stringList(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// composite walks every bucket of a composite aggregation over the alerts.
// Paging through after_key, it has no limit on the number of agents or
// accounts: a terms aggregation would cut silently at its size.
func (s *Source) composite(ctx context.Context, filter, sources []any, sub map[string]any, fn func(key map[string]any, bucket json.RawMessage) error) error {
	return s.compositeIn(ctx, s.index, filter, sources, sub, fn)
}

func (s *Source) compositeIn(ctx context.Context, index string, filter, sources []any, sub map[string]any, fn func(key map[string]any, bucket json.RawMessage) error) error {

	var after map[string]any

	for {
		agg := map[string]any{"size": compositePage, "sources": sources}
		if after != nil {
			agg["after"] = after
		}

		body := map[string]any{"composite": agg}
		if sub != nil {
			body["aggs"] = sub
		}

		query := map[string]any{
			"size":  0,
			"query": map[string]any{"bool": map[string]any{"filter": filter}},
			"aggs":  map[string]any{"c": body},
		}

		var resp struct {
			Aggregations struct {
				C struct {
					AfterKey map[string]any    `json:"after_key"`
					Buckets  []json.RawMessage `json:"buckets"`
				} `json:"c"`
			} `json:"aggregations"`
		}

		if err := s.client.Search(ctx, index, query, &resp); err != nil {
			return err
		}

		for _, b := range resp.Aggregations.C.Buckets {
			var head struct {
				Key map[string]any `json:"key"`
			}
			if err := json.Unmarshal(b, &head); err != nil {
				return err
			}
			if err := fn(head.Key, b); err != nil {
				return err
			}
		}

		if len(resp.Aggregations.C.Buckets) < compositePage || resp.Aggregations.C.AfterKey == nil {
			return nil
		}
		after = resp.Aggregations.C.AfterKey
	}
}

func terms(name, field string) any {
	return map[string]any{name: map[string]any{"terms": map[string]any{"field": field, "missing_bucket": true}}}
}

func keyString(key map[string]any, name string) string {
	if v, ok := key[name].(string); ok {
		return v
	}
	return ""
}

// MethodCount is how many successful logins of a service used one set of
// factors ("otp+password": sorted, joined by +; "" when none was written).
type MethodCount struct {
	Service string
	Factors string
	Count   int
}

// ServiceMethods counts the successful logins of one agent since the given
// time by service and factor set.
func (s *Source) ServiceMethods(ctx context.Context, agentID string, since time.Time) ([]MethodCount, error) {
	return batched(ctx, s, "methods|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]MethodCount, error) {
		return s.serviceMethods(ctx, ids, since)
	})
}

func (s *Source) serviceMethods(ctx context.Context, ids []string, since time.Time) (map[string][]MethodCount, error) {

	filter := serviceFilter(ids, since, termFilter("data.tipo", "autenticacion"), termFilter("data.resultado", "exito"))

	script := map[string]any{"m": map[string]any{"terms": map[string]any{
		"script": map[string]any{
			"lang":   "painless",
			"source": "def f = doc['data.factores']; if (f.size() == 0) { return ''; } return String.join('+', f);",
		},
	}}}

	out := map[string][]MethodCount{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("s", "data.oscompliance_service"), script}, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			DocCount int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		out[keyString(key, "a")] = append(out[keyString(key, "a")], MethodCount{Service: keyString(key, "s"), Factors: keyString(key, "m"), Count: c.DocCount})
		return nil
	})

	return out, err
}

// CertificateCount is how many certificate logins of a service had one
// issuer and one revocation check ("" when not written).
type CertificateCount struct {
	Service, Issuer, Revocation string
	Count                       int
}

// ServiceCertificates counts the certificate and card logins of one agent
// since the given time by service, issuer and revocation check.
func (s *Source) ServiceCertificates(ctx context.Context, agentID string, since time.Time) ([]CertificateCount, error) {
	return batched(ctx, s, "certificates|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]CertificateCount, error) {
		return s.serviceCertificates(ctx, ids, since)
	})
}

func (s *Source) serviceCertificates(ctx context.Context, ids []string, since time.Time) (map[string][]CertificateCount, error) {

	filter := serviceFilter(ids, since,
		termFilter("data.tipo", "autenticacion"), termFilter("data.resultado", "exito"),
		termFilter("data.factores", "certificado", "tarjeta"))

	out := map[string][]CertificateCount{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("s", "data.oscompliance_service"), terms("i", "data.certificado_emisor"), terms("r", "data.revocacion")}, nil,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				DocCount int `json:"doc_count"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			out[keyString(key, "a")] = append(out[keyString(key, "a")], CertificateCount{Service: keyString(key, "s"), Issuer: keyString(key, "i"), Revocation: keyString(key, "r"), Count: c.DocCount})
			return nil
		})

	return out, err
}

// Burst bounds the failed logins of one key (an origin, an account) of a
// service within any span.
type Burst struct {
	Service, Key string
	// AtMost is an upper bound of the failures within any span: the sum of
	// two neighbouring span-long buckets, which cover every stretch of that
	// length. The judge counts exactly only where the bound is too high.
	AtMost int
	Total  int
}

// ServiceFailureBursts returns, per service and value of field (data.origen,
// data.usuario), an upper bound of the failed logins within any span.
func (s *Source) ServiceFailureBursts(ctx context.Context, agentID string, since time.Time, field string, span time.Duration) ([]Burst, error) {
	return batched(ctx, s, fmt.Sprint("bursts|", sinceKey(since), field, span), agentID, func(ctx context.Context, ids []string) (map[string][]Burst, error) {
		return s.serviceFailureBursts(ctx, ids, since, field, span)
	})
}

func (s *Source) serviceFailureBursts(ctx context.Context, ids []string, since time.Time, field string, span time.Duration) (map[string][]Burst, error) {

	filter := serviceFilter(ids, since, termFilter("data.tipo", "autenticacion"), termFilter("data.resultado", "fallo"))

	sub := map[string]any{"t": map[string]any{"date_histogram": map[string]any{
		"field": "timestamp", "fixed_interval": fmt.Sprintf("%ds", int(span.Seconds())), "min_doc_count": 1,
	}}}

	out := map[string][]Burst{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("s", "data.oscompliance_service"), terms("k", field)}, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			DocCount int `json:"doc_count"`
			T        struct {
				Buckets []struct {
					DocCount int `json:"doc_count"`
				} `json:"buckets"`
			} `json:"t"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		burst := Burst{Service: keyString(key, "s"), Key: keyString(key, "k"), Total: c.DocCount}
		for i, bucket := range c.T.Buckets {
			// Two neighbouring buckets cover any span-long stretch.
			n := bucket.DocCount
			if i+1 < len(c.T.Buckets) {
				n += c.T.Buckets[i+1].DocCount
			}
			burst.AtMost = max(burst.AtMost, n)
		}
		out[keyString(key, "a")] = append(out[keyString(key, "a")], burst)
		return nil
	})

	return out, err
}

// MessageCount is how many rejections of a service showed one message.
type MessageCount struct {
	Service, Message string
	Count            int
}

// ServiceMessages counts the rejection messages of one agent since the
// given time by service.
func (s *Source) ServiceMessages(ctx context.Context, agentID string, since time.Time) ([]MessageCount, error) {
	return batched(ctx, s, "messages|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]MessageCount, error) {
		return s.serviceMessages(ctx, ids, since)
	})
}

func (s *Source) serviceMessages(ctx context.Context, ids []string, since time.Time) (map[string][]MessageCount, error) {

	filter := serviceFilter(ids, since, termFilter("data.tipo", "autenticacion"), termFilter("data.resultado", "fallo"),
		map[string]any{"exists": map[string]any{"field": "data.mensaje"}})

	out := map[string][]MessageCount{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("s", "data.oscompliance_service"), terms("m", "data.mensaje")}, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			DocCount int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		out[keyString(key, "a")] = append(out[keyString(key, "a")], MessageCount{Service: keyString(key, "s"), Message: keyString(key, "m"), Count: c.DocCount})
		return nil
	})

	return out, err
}

// ServiceAccount is what the index holds about one account of a service.
type ServiceAccount struct {
	Service, User string
	LastSuccess   time.Time // zero: never
	LastChange    time.Time // zero: no credential change recorded
	LastDisabled  time.Time // zero: never disabled
}

// ServiceAccounts returns every account of one agent's services that ever
// logged in, changed its credential or was disabled, as far back as the
// index goes.
func (s *Source) ServiceAccounts(ctx context.Context, agentID string) ([]ServiceAccount, error) {
	return batched(ctx, s, "accounts", agentID, s.serviceAccounts)
}

func (s *Source) serviceAccounts(ctx context.Context, ids []string) (map[string][]ServiceAccount, error) {

	filter := serviceFilter(ids, time.Time{},
		termFilter("data.tipo", "autenticacion", "cambio_credencial", "inhabilitacion"),
		map[string]any{"exists": map[string]any{"field": "data.usuario"}})

	newest := func(conditions ...any) map[string]any {
		return map[string]any{
			"filter": map[string]any{"bool": map[string]any{"filter": conditions}},
			"aggs":   map[string]any{"t": map[string]any{"max": map[string]any{"field": "timestamp"}}},
		}
	}

	sub := map[string]any{
		"success":  newest(termFilter("data.tipo", "autenticacion"), termFilter("data.resultado", "exito")),
		"change":   newest(termFilter("data.tipo", "cambio_credencial")),
		"disabled": newest(termFilter("data.tipo", "inhabilitacion")),
	}

	out := map[string][]ServiceAccount{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("s", "data.oscompliance_service"), terms("u", "data.usuario")}, sub, func(key map[string]any, b json.RawMessage) error {

		var c struct {
			Success, Change, Disabled struct {
				T struct {
					Value *float64 `json:"value"`
				} `json:"t"`
			}
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}

		at := func(v *float64) time.Time {
			if v == nil {
				return time.Time{}
			}
			return time.UnixMilli(int64(*v)).UTC()
		}

		out[keyString(key, "a")] = append(out[keyString(key, "a")], ServiceAccount{
			Service: keyString(key, "s"), User: keyString(key, "u"),
			LastSuccess: at(c.Success.T.Value), LastChange: at(c.Change.T.Value), LastDisabled: at(c.Disabled.T.Value),
		})
		return nil
	})

	return out, err
}

// ServiceSpan is the oldest and newest event of one service in the index.
type ServiceSpan struct {
	Oldest, Newest time.Time
	Count          int
}

// ServiceSpans returns, per service of one agent, the oldest and newest
// event the index keeps.
func (s *Source) ServiceSpans(ctx context.Context, agentID string) (map[string]ServiceSpan, error) {
	return batched(ctx, s, "spans", agentID, s.serviceSpans)
}

func (s *Source) serviceSpans(ctx context.Context, ids []string) (map[string]map[string]ServiceSpan, error) {

	sub := map[string]any{
		"o": map[string]any{"min": map[string]any{"field": "timestamp"}},
		"n": map[string]any{"max": map[string]any{"field": "timestamp"}},
	}

	out := map[string]map[string]ServiceSpan{}
	for _, id := range ids {
		out[id] = map[string]ServiceSpan{}
	}

	err := s.composite(ctx, serviceFilter(ids, time.Time{}), []any{terms("a", "agent.id"), terms("s", "data.oscompliance_service")}, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			DocCount int `json:"doc_count"`
			O, N     struct {
				Value float64 `json:"value"`
			}
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		if out[keyString(key, "a")] == nil {
			out[keyString(key, "a")] = map[string]ServiceSpan{}
		}
		out[keyString(key, "a")][keyString(key, "s")] = ServiceSpan{Oldest: time.UnixMilli(int64(c.O.Value)).UTC(), Newest: time.UnixMilli(int64(c.N.Value)).UTC(), Count: c.DocCount}
		return nil
	})

	return out, err
}

// ServiceLogSnapshots returns, per agent, the newest service_log_snapshot.
func (s *Source) ServiceLogSnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.ServiceLogSnapshot, error) {
	return latestFacts[fact.ServiceLogSnapshot](ctx, s, fact.ServiceLogSnapshotFact, since, n)
}

// ServiceLogs returns every service_log of one read of one agent.
func (s *Source) ServiceLogs(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ServiceLog, error) {
	return passRecords[fact.ServiceLog](ctx, s, fact.ServiceLogFact, agentID, runID, since)
}

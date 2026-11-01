package source

import (
	"context"
	"encoding/json"
	"time"
)

// CloudOperation is a successful administrative operation a cloud module brought into Wazuh, by actor.
type CloudOperation struct {
	Module    string
	Actor     string
	Operation string
	Count     int
	Last      time.Time
}

// cloudAdmin says, for each cloud module whose records name the actor, what makes an alert a successful
// administrative operation and which fields name its actor and operation.
var cloudAdmin = []struct {
	module, actor, operation string
	filter                   []any
}{
	{"aws-s3", "data.aws.userIdentity.arn", "data.aws.eventName", []any{
		map[string]any{"term": map[string]any{"data.aws.readOnly": "false"}},
		map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"exists": map[string]any{"field": "data.aws.errorCode"}}}}},
	}},
	{"office365", "data.office365.UserId", "data.office365.Operation", []any{
		map[string]any{"terms": map[string]any{"data.office365.RecordType": []any{"1", "8"}}},
		map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"terms": map[string]any{"data.office365.ResultStatus": []any{"Failed", "Failure"}}}}}},
	}},
}

// CloudAdminModules are the modules whose administrative operations the engine reads.
func CloudAdminModules() []string {
	out := make([]string, len(cloudAdmin))
	for i, c := range cloudAdmin {
		out[i] = c.module
	}
	return out
}

// CloudAdminOperations are the successful administrative operations of the cloud modules since a time.
func (s *Source) CloudAdminOperations(ctx context.Context, since time.Time) ([]CloudOperation, error) {

	var out []CloudOperation
	sub := map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}}

	for _, c := range cloudAdmin {
		filter := append([]any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}}}, c.filter...)
		err := s.composite(ctx, filter, []any{terms("a", c.actor), terms("o", c.operation)}, sub, func(key map[string]any, b json.RawMessage) error {
			d, err := detectionOf(b)
			if err != nil {
				return err
			}
			out = append(out, CloudOperation{Module: c.module, Actor: keyString(key, "a"), Operation: keyString(key, "o"), Count: d.Count, Last: d.Last})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

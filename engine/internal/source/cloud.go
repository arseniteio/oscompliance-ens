package source

import (
	"context"
	"encoding/json"
	"time"
)

type CloudOperation struct {
	Module    string
	Actor     string
	Operation string
	Count     int
	Last      time.Time
}

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
	{"azure-logs", "data.Caller", "data.OperationNameValue", []any{
		map[string]any{"term": map[string]any{"data.CategoryValue": "Administrative"}},
		map[string]any{"term": map[string]any{"data.ActivityStatusValue": "Succeeded"}},
	}},
	{"ms-graph", "data.ms-graph.initiatedBy.user.userPrincipalName", "data.ms-graph.activityDisplayName", []any{
		map[string]any{"term": map[string]any{"data.ms-graph.result": "success"}},
	}},
	{"gcp-pubsub", "data.gcp.protoPayload.authenticationInfo.principalEmail", "data.gcp.protoPayload.methodName", gcpAdminActivity},
	{"gcp-bucket", "data.gcp.protoPayload.authenticationInfo.principalEmail", "data.gcp.protoPayload.methodName", gcpAdminActivity},
}

var gcpAdminActivity = []any{
	map[string]any{"wildcard": map[string]any{"data.gcp.logName": "*cloudaudit.googleapis.com%2Factivity"}},
	map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"exists": map[string]any{"field": "data.gcp.protoPayload.status.code"}}}}},
}

func CloudAdminModules() []string {
	out := make([]string, len(cloudAdmin))
	for i, c := range cloudAdmin {
		out[i] = c.module
	}
	return out
}

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

func (s *Source) GroupFindings(ctx context.Context, groups []string, level int, since time.Time) (all, serious Detection, err error) {
	if all, err = s.GroupDetections(ctx, groups, since); err != nil {
		return all, serious, err
	}
	names := make([]any, len(groups))
	for i, g := range groups {
		names[i] = g
	}
	query := map[string]any{
		"size": 0, "track_total_hits": true,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"rule.groups": names}},
			map[string]any{"range": map[string]any{"rule.level": map[string]any{"gte": level}}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		}}},
		"aggs": map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}},
	}
	var resp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations json.RawMessage `json:"aggregations"`
	}
	if err = s.client.Search(ctx, s.index, query, &resp); err != nil {
		return all, serious, err
	}
	serious, err = detectionOf(resp.Aggregations)
	serious.Count = resp.Hits.Total.Value
	return all, serious, err
}

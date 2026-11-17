package wintime

import (
	_ "embed"
	"slices"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed time.ps1
var script string

const Tool = "w32time"

type output struct {
	Running   bool     `json:"running"`
	Type      string   `json:"type"`
	NTPServer string   `json:"ntp_server"`
	Status    []string `json:"status"`
}

// w32tm /query /status is translated, so it is read by line position:
// leap indicator first, stratum second, source eighth.
const (
	leapLine    = 0
	stratumLine = 1
	sourceLine  = 7
	leapAlarm   = 3
)

func Collect(e *emit.Emitter, run winps.Runner) error {

	s := fact.TimeSync{Envelope: e.Envelope(fact.TimeSyncFact), Tool: "none", Status: fact.SourceRead, Sources: []string{}}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}
	if !out.Running || strings.EqualFold(out.Type, "NoSync") {
		return e.Emit(s)
	}

	s.Tool = Tool
	values := lineValues(out.Status)
	leap, leapOK := leadingNumber(at(values, leapLine))
	stratum, stratumOK := leadingNumber(at(values, stratumLine))
	s.Synchronised = leapOK && stratumOK && leap != leapAlarm && stratum >= 1 && stratum <= 15

	if src := at(values, sourceLine); src != "" {
		s.Sources = append(s.Sources, src)
	}
	for _, peer := range strings.Fields(out.NTPServer) {
		if host, _, _ := strings.Cut(peer, ","); !slices.Contains(s.Sources, host) {
			s.Sources = append(s.Sources, host)
		}
	}
	// NT5DS takes the time from the domain hierarchy, which signs it with the machine account.
	s.Authenticated = strings.EqualFold(out.Type, "NT5DS")

	return e.Emit(s)
}

func lineValues(lines []string) []string {
	var out []string
	for _, l := range lines {
		if _, v, ok := strings.Cut(l, ":"); ok {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

func at(values []string, i int) string {
	if i < len(values) {
		return values[i]
	}
	return ""
}

func leadingNumber(v string) (int, bool) {
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end < 0 {
		end = len(v)
	}
	n, err := strconv.Atoi(v[:end])
	return n, err == nil
}

package opacc6

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

const (
	ReqR11 = "op.acc.6.r1.1"
	ReqR21 = "op.acc.6.r2.1"
	ReqR81 = "op.acc.6.r8.1"
)

var secondFactorModules = map[string]bool{
	"pam_google_authenticator.so": true, "pam_oath.so": true, "pam_u2f.so": true,
	"pam_duo.so": true, "pam_radius_auth.so": true, "pam_yubico.so": true, "pam_totp.so": true,
}

type EV02Input struct {
	Logins    []source.Login
	Listening Listening
	Settings  Settings
	PAM       PAM
	Log       passes.AuthLog

	Zones        Zones
	ZonesProblem catalog.Message
}

type access struct {
	what       catalog.Message
	controlled bool
	zoneKnown  bool
	factors    int
	password   bool
}

func JudgeEV02(in EV02Input) map[string]verdict.Judgement {

	out := map[string]verdict.Judgement{}

	gap, found := ev02Gap(in)

	for _, req := range []string{ReqR81, ReqR11, ReqR21} {
		if found {
			out[req] = gap
			continue
		}
		out[req] = judgeZone(req, in)
	}

	return out
}

func ev02Gap(in EV02Input) (verdict.Judgement, bool) {

	if !in.ZonesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ZonesProblem), true
	}
	if gap, found := in.Settings.Gap(); found {
		return gap, true
	}
	if gap, found := in.PAM.Gap(); found {
		return gap, true
	}
	if gap, found := in.Listening.Gap(); found {
		return gap, true
	}

	return verdict.Judgement{}, false
}

func judgeZone(req string, in EV02Input) verdict.Judgement {

	sshd := in.Settings.SSHD()
	match := in.Settings.HasMatch()

	needsTwo := func(a access) bool {
		switch req {
		case ReqR81:
			return !a.controlled
		case ReqR11:
			return !a.controlled && a.password
		}
		return true
	}

	var failing, unknown []catalog.Message

	for _, a := range accesses(in.Logins, in.Zones, sshd, in.PAM) {

		if !a.zoneKnown && req != ReqR21 {
			unknown = append(unknown, catalog.Says("opacc6.origin_not_address", "what", a.what))
			continue
		}
		if !needsTwo(a) {
			continue
		}

		switch {
		case a.factors == 0:
			unknown = append(unknown, catalog.Says("opacc6.factors_unknown", "what", a.what))
		case a.factors < 2 && match:
			unknown = append(unknown, catalog.Says("opacc6.one_factor_match", "what", a.what))
		case a.factors < 2:
			failing = append(failing, catalog.Says("opacc6.one_factor", "what", a.what))
		}
	}

	channels, _ := in.Listening.Channels()

	for _, c := range channels {

		if c.Kind != KindAuthentication {
			continue
		}

		minimum, password, known := channelFactors(c, sshd, in.PAM)

		var exposed []string
		for _, addr := range in.Listening.Exposed(c) {
			if controlled, _ := in.Zones.Controlled(addr); !controlled {
				exposed = append(exposed, addr)
			}
		}

		a := access{what: catalog.Says("opacc6.channel", "name", c.Name), controlled: len(exposed) == 0, zoneKnown: true, factors: minimum, password: password}
		if len(exposed) > 0 {
			a.what = catalog.Says("opacc6.channel_on", "name", c.Name, "addresses", exposed)
		}

		switch {
		case !needsTwo(a):
		case !known:
			unknown = append(unknown, catalog.Says("opacc6.channel_factors_unknown", "what", a.what))
		case minimum < 2 && match && c.Name == "ssh":
			unknown = append(unknown, catalog.Says("opacc6.accepts_one_factor_match", "what", a.what))
		case minimum < 2:
			failing = append(failing, catalog.Says("opacc6.accepts_one_factor", "what", a.what))
		}
	}

	if len(failing) > 0 {
		catalog.SortMessages(failing)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		catalog.SortMessages(unknown)
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	if len(in.Logins) == 0 && !in.Log.Reaches {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.logins_cannot_be_seen_a", "a", in.Log.Detail))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_logins_and_b_channels_examined_two_fac", "a", len(in.Logins), "b", len(channels), "c", req))
}

func accesses(logins []source.Login, zones Zones, sshd SSHD, pam PAM) []access {

	seen := map[string]bool{}
	var out []access

	for _, l := range logins {

		origin := l.SourceIP
		if l.Method != source.MethodSSHD {
			origin = "local"
		}

		key := strings.Join([]string{l.Account, origin, l.Method, l.Auth, l.KeyType}, "|")
		if seen[key] {
			continue
		}
		seen[key] = true

		a := access{what: catalog.Says("opacc6.login_of", "method", l.Method, "account", l.Account, "origin", origin)}
		a.controlled, a.zoneKnown = zones.Controlled(origin)

		switch l.Method {
		case source.MethodSSHD:
			a.factors, a.password = sshdLoginFactors(l, sshd, pam)
		case source.MethodSU:

			continue
		default:
			a.factors, a.password = 1, true
			if hasSecondFactor(pam, "login") {
				a.factors = 2
			}
		}

		out = append(out, a)
	}

	return out
}

func sshdLoginFactors(l source.Login, sshd SSHD, pam PAM) (factors int, password bool) {

	switch {
	case l.Auth == "publickey":
		factors = 1
		if strings.HasSuffix(strings.ToUpper(l.KeyType), "-SK") && strings.Contains(sshd.Get("pubkeyauthoptions"), "verify-required") {
			factors = 2
		}
	case l.Auth == "password":
		factors, password = 1, true
	case strings.HasPrefix(l.Auth, "keyboard-interactive"):
		factors, password = 1, true
		if hasSecondFactor(pam, "sshd") {
			factors = 2
		}
	case l.Auth == "":
		return 0, false
	default:
		factors = 1
	}

	if required := authenticationMethods(sshd, pam); required > factors {
		factors = required
	}

	return factors, password
}

func channelFactors(c Channel, sshd SSHD, pam PAM) (minimum int, password, known bool) {

	switch c.Name {
	case "ssh":
		if sshd.Status != fact.SourceRead {
			return 0, false, false
		}
		password = sshd.Get("passwordauthentication") == "yes" || sshd.Get("kbdinteractiveauthentication") == "yes"
		if required := authenticationMethods(sshd, pam); required > 0 {
			return required, password, true
		}
		minimum = 2
		for _, m := range enabledMethods(sshd, pam) {
			minimum = min(minimum, m)
		}
		return minimum, password, true
	case "ldap", "ldaps", "telnet", "ftp", "vnc":
		return 1, true, true
	}

	return 0, true, false
}

func enabledMethods(sshd SSHD, pam PAM) []int {

	var out []int

	if sshd.Get("pubkeyauthentication") == "yes" {
		out = append(out, 1)
	}
	if sshd.Get("passwordauthentication") == "yes" {
		out = append(out, 1)
	}
	if sshd.Get("kbdinteractiveauthentication") == "yes" {
		n := 1
		if hasSecondFactor(pam, "sshd") {
			n = 2
		}
		out = append(out, n)
	}

	return out
}

func authenticationMethods(sshd SSHD, pam PAM) int {

	value := sshd.Get("authenticationmethods")
	if value == "" || value == "any" {
		return 0
	}

	fewest := 0

	for _, list := range strings.Fields(value) {

		sum := 0
		for _, method := range strings.Split(list, ",") {
			method, _, _ = strings.Cut(method, ":")
			n := 1
			if method == "keyboard-interactive" && hasSecondFactor(pam, "sshd") {
				n = 2
			}
			sum += n
		}

		if fewest == 0 || sum < fewest {
			fewest = sum
		}
	}

	return fewest
}

func hasSecondFactor(pam PAM, service string) bool {

	for _, r := range pam.Stack(service, "auth") {
		if secondFactorModules[r.Module] && r.Control != "optional" && r.Control != "sufficient" {
			return true
		}
	}

	return false
}

func worst(decisions ...verdict.Judgement) verdict.Judgement {

	rank := map[verdict.Status]int{verdict.NonCompliant: 3, verdict.NotEvaluable: 2, verdict.Compliant: 1}
	best := verdict.Judgement{}

	for _, d := range decisions {
		if rank[d.Status] > rank[best.Status] {
			best = d
		}
	}

	return best
}

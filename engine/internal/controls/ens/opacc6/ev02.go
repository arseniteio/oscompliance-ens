package opacc6

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Requirements judged from EV-02.
const (
	ReqR11 = "op.acc.6.r1.1" // R1: password only from a controlled zone
	ReqR21 = "op.acc.6.r2.1" // R2: a second factor with the password
	ReqR81 = "op.acc.6.r8.1" // R8: two factors from an uncontrolled zone
)

// secondFactorModules are PAM modules that verify a second factor.
var secondFactorModules = map[string]bool{
	"pam_google_authenticator.so": true, "pam_oath.so": true, "pam_u2f.so": true,
	"pam_duo.so": true, "pam_radius_auth.so": true, "pam_yubico.so": true, "pam_totp.so": true,
}

// EV02Input is what EV-02 (factors by zone) needs.
type EV02Input struct {
	Logins    []source.Login // in the window
	Listening Listening
	Settings  Settings
	PAM       PAM
	Log       passes.AuthLog

	// Zones is P-02; ZonesProblem says why it cannot be used.
	Zones        Zones
	ZonesProblem string
}

// access is one login with the factors it proved and its zone.
type access struct {
	what       string
	controlled bool
	zoneKnown  bool
	factors    int // 0: unknown
	password   bool
}

// JudgeEV02 judges the three requirements EV-02 serves, as described in
// catalog/docs/contracts/op.acc.6.md. Each one looks at the logins of the
// window and at the authentication channels listening:
//
//   - r8.1: a login from an uncontrolled zone with one factor, or a channel
//     answering on an uncontrolled address that accepts one factor.
//   - r1.1: the same, for logins and channels that use a password.
//   - r2.1: any login or channel with one factor.
//
// Factors: publickey is one, two with a FIDO key (-SK) and
// PubkeyAuthOptions verify-required; password one; keyboard-interactive two
// when the sshd PAM stack requires a second-factor module; the console
// likewise from the login stack. sshd AuthenticationMethods raises the
// count to its weakest list. A Match block in sshd_config can change all of
// this per user: what would fail becomes NOT_EVALUABLE.
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

// ev02Gap: what stops all three.
func ev02Gap(in EV02Input) (verdict.Judgement, bool) {

	if in.ZonesProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-02: "+in.ZonesProblem), true
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

	var failing, unknown []string

	// Logins.
	for _, a := range accesses(in.Logins, in.Zones, sshd, in.PAM) {

		if !a.zoneKnown && req != ReqR21 {
			unknown = append(unknown, a.what+": origin is not an address")
			continue
		}
		if !needsTwo(a) {
			continue
		}

		switch {
		case a.factors == 0:
			unknown = append(unknown, a.what+": factors unknown")
		case a.factors < 2 && match:
			unknown = append(unknown, a.what+": one factor by the global sshd configuration, but a Match block may change it")
		case a.factors < 2:
			failing = append(failing, a.what+": one factor")
		}
	}

	// Channels.
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

		a := access{what: "channel " + c.Name, controlled: len(exposed) == 0, zoneKnown: true, factors: minimum, password: password}
		if len(exposed) > 0 {
			a.what += " on " + strings.Join(exposed, ", ")
		}

		switch {
		case !needsTwo(a):
		case !known:
			unknown = append(unknown, a.what+": factors it requires unknown")
		case minimum < 2 && match && c.Name == "ssh":
			unknown = append(unknown, a.what+": accepts one factor by the global configuration, but a Match block may change it")
		case minimum < 2:
			failing = append(failing, a.what+": accepts one factor")
		}
	}

	if len(failing) > 0 {
		sort.Strings(failing)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(failing, "; ")}
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	// Silence about logins needs the log to reach Wazuh.
	if len(in.Logins) == 0 && !in.Log.Reaches {
		return passes.NotEvaluable(verdict.CauseCollection, "logins cannot be seen: "+in.Log.Detail)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d logins and %d channels examined, two factors wherever %s requires them", len(in.Logins), len(channels), req)}
}

// accesses classifies the logins of the window, one entry per account,
// origin and method.
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

		a := access{what: fmt.Sprintf("%s login of %s from %s", l.Method, l.Account, origin)}
		a.controlled, a.zoneKnown = zones.Controlled(origin)

		switch l.Method {
		case source.MethodSSHD:
			a.factors, a.password = sshdLoginFactors(l, sshd, pam)
		case source.MethodSU:
			// su is not a login into the machine: the person is already in.
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

// sshdLoginFactors counts the factors of one sshd login.
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
		factors = 1 // hostbased, gssapi-with-mic: one proof
	}

	if required := authenticationMethods(sshd, pam); required > factors {
		factors = required
	}

	return factors, password
}

// channelFactors is the fewest factors a channel accepts; password says
// whether it takes a password at all.
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

	// rdp, cockpit, webmin: depends on their own configuration.
	return 0, true, false
}

// enabledMethods is the factor count of each sshd method enabled.
func enabledMethods(sshd SSHD, pam PAM) []int {

	var out []int

	// A key is one factor: verify-required only adds one for FIDO keys,
	// and the configuration does not say that every key is one.
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

// authenticationMethods is the fewest factors of the AuthenticationMethods
// lists ("publickey,keyboard-interactive publickey,password"), 0 for "any".
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

// hasSecondFactor: the auth stack of the service requires a second-factor
// module (not optional, not sufficient: those can be skipped).
func hasSecondFactor(pam PAM, service string) bool {

	for _, r := range pam.Stack(service, "auth") {
		if secondFactorModules[r.Module] && r.Control != "optional" && r.Control != "sufficient" {
			return true
		}
	}

	return false
}

// worst is the EV-02 evidence verdict from the decisions that apply:
// NON_COMPLIANT over NOT_EVALUABLE over COMPLIANT.
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

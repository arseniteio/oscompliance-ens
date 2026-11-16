package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/hostprofile"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
)

const passwordEnv = "OSC_INDEXER_PASSWORD"

const usage = `usage: oscompliance-policy <command> [flags] [arguments]

  check FILE...            validate profiles without connecting
  plan FILE...             show what apply would change
  apply FILE...            write the profiles to the indexer
  export [-builtin] [ID...] print the stored profiles as YAML
  delete ID...             remove stored profiles
  explain -agent ID        show the profiles and values one machine gets

Run "oscompliance-policy <command> -h" for the flags of a command.
`

type options struct {
	indexer     string
	user        string
	ca          string
	configIndex string
	hostIndex   string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "oscompliance-policy:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {

	if len(args) == 0 || args[0] == "-h" || args[0] == "help" {
		_, err := fmt.Fprint(out, usage)
		return err
	}

	command, rest := args[0], args[1:]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	var o options
	if command != "check" {
		fs.StringVar(&o.indexer, "indexer", "https://localhost:9200", "indexer URLs, comma-separated")
		fs.StringVar(&o.user, "user", "admin", "indexer user; password in $"+passwordEnv)
		fs.StringVar(&o.ca, "ca", "", "CA certificate for the indexer (PEM)")
		fs.StringVar(&o.configIndex, "config-index", "wazuh-ens-configuration", "index holding the profiles")
	}
	builtin := fs.Bool("builtin", false, "export: include the built-in profiles")
	agent := fs.String("agent", "", "explain: Wazuh agent ID")
	control := fs.String("control", "", "explain: only this control, such as op.acc.1")
	if command == "explain" {
		fs.StringVar(&o.hostIndex, "host-profile-index", "oscompliance-host-profile", "index of the machines' host profiles")
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}

	ctx := context.Background()

	switch command {
	case "check":
		_, err := readProfiles(fs.Args(), true, out)
		return err
	case "plan", "apply":
		files, err := readProfiles(fs.Args(), false, out)
		if err != nil {
			return err
		}
		client, err := connect(o)
		if err != nil {
			return err
		}
		return planApply(ctx, client, o.configIndex, files, command == "apply", out)
	case "export":
		client, err := connect(o)
		if err != nil {
			return err
		}
		return export(ctx, client, o.configIndex, fs.Args(), *builtin, out)
	case "delete":
		client, err := connect(o)
		if err != nil {
			return err
		}
		return remove(ctx, client, o.configIndex, fs.Args(), out)
	case "explain":
		if *agent == "" {
			return errors.New("explain needs -agent")
		}
		client, err := connect(o)
		if err != nil {
			return err
		}
		return explain(ctx, client, o, *agent, *control, out)
	}

	return fmt.Errorf("unknown command %q\n\n%s", command, usage)
}

func connect(o options) (*indexer.Client, error) {
	return indexer.New(o.indexer, o.user, os.Getenv(passwordEnv), o.ca)
}

func readProfiles(paths []string, listOK bool, out io.Writer) ([]catalog.Profile, error) {

	rep := &report{w: out}

	if len(paths) == 0 {
		return nil, errors.New("name at least one YAML file")
	}

	var all []catalog.Profile
	where := map[string]string{}
	failed := 0

	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		profiles, err := decodeYAML(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, prof := range profiles {
			errs := prof.Validate()
			if first, dup := where[prof.ID]; dup {
				errs = append(errs, fmt.Sprintf("%s: also defined in %s", prof.ID, first))
			}
			where[prof.ID] = p
			if len(errs) > 0 {
				failed++
				for _, e := range errs {
					rep.printf("ERROR %s: %s\n", p, e)
				}
				continue
			}
			if listOK {
				rep.printf("ok    %s: %s (%s)\n", p, prof.ID, prof.Layer)
			}
			all = append(all, prof)
		}
	}

	if failed > 0 {
		return nil, fmt.Errorf("%d profiles have errors", failed)
	}
	return all, rep.err
}

func stored(ctx context.Context, client *indexer.Client, index string) (map[string]catalog.Profile, error) {
	list, err := params.LoadProfiles(ctx, client, index)
	if err != nil && list == nil {
		return nil, err
	}
	byID := map[string]catalog.Profile{}
	for _, p := range list {
		byID[p.ID] = p
	}
	return byID, nil
}

func planApply(ctx context.Context, client *indexer.Client, index string, files []catalog.Profile, apply bool, out io.Writer) error {

	rep := &report{w: out}

	current, err := stored(ctx, client, index)
	if err != nil {
		return err
	}
	builtins := map[string]bool{}
	for _, p := range catalog.BuiltinProfiles() {
		builtins[p.ID] = true
	}

	var changed []catalog.Profile
	for _, p := range files {
		old, exists := current[p.ID]
		diff := profileDiff(old, p)
		switch {
		case !exists && builtins[p.ID]:
			rep.printf("new      %s (replaces the built-in profile)\n", p.ID)
		case !exists:
			rep.printf("new      %s\n", p.ID)
		case len(diff) == 0:
			rep.printf("same     %s\n", p.ID)
			continue
		default:
			rep.printf("changed  %s: %s\n", p.ID, strings.Join(diff, ", "))
		}
		changed = append(changed, p)
	}
	for _, id := range sortedKeys(current) {
		if !slices.ContainsFunc(files, func(p catalog.Profile) bool { return p.ID == id }) {
			rep.printf("kept     %s (stored, not in the files; remove it with delete)\n", id)
		}
	}

	if !apply {
		if len(changed) > 0 {
			rep.printf("\n%d profiles would be written. Run apply to write them.\n", len(changed))
		}
		return rep.err
	}

	by := "oscompliance-policy"
	if u, err := user.Current(); err == nil {
		by += " (" + u.Username + ")"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, p := range changed {
		doc := map[string]any{
			"documentType":  params.ProfileDocumentType,
			"configuration": p,
			"updatedAt":     now,
			"updatedBy":     by,
		}
		if err := client.Put(ctx, index, params.ProfileDocumentID(p.ID), doc); err != nil {
			return fmt.Errorf("%s: %w", p.ID, err)
		}
	}
	if err := client.Refresh(ctx, index); err != nil {
		return err
	}
	rep.printf("\n%d profiles written. The engine uses them from its next pass.\n", len(changed))
	return rep.err
}

func export(ctx context.Context, client *indexer.Client, index string, ids []string, builtin bool, out io.Writer) error {

	current, err := stored(ctx, client, index)
	if err != nil {
		return err
	}
	for _, p := range catalog.BuiltinProfiles() {
		if _, overridden := current[p.ID]; !overridden && (builtin || slices.Contains(ids, p.ID)) {
			current[p.ID] = p
		}
	}

	var list []catalog.Profile
	for _, id := range sortedKeys(current) {
		if len(ids) == 0 || slices.Contains(ids, id) {
			list = append(list, current[id])
		}
	}
	for _, id := range ids {
		if _, ok := current[id]; !ok {
			return fmt.Errorf("no profile %s", id)
		}
	}

	if len(list) == 0 {
		return nil
	}
	raw, err := encodeYAML(list)
	if err != nil {
		return err
	}
	_, err = out.Write(raw)
	return err
}

func remove(ctx context.Context, client *indexer.Client, index string, ids []string, out io.Writer) error {

	rep := &report{w: out}

	if len(ids) == 0 {
		return errors.New("name the profiles to delete")
	}
	for _, id := range ids {
		path := "/" + url.PathEscape(index) + "/_doc/" + url.PathEscape(params.ProfileDocumentID(id)) + "?refresh=true"
		err := client.Do(ctx, http.MethodDelete, path, nil, nil)
		var e *indexer.Error
		if errors.As(err, &e) && e.Status == http.StatusNotFound {
			return fmt.Errorf("no stored profile %s", id)
		}
		if err != nil {
			return err
		}
		rep.printf("deleted  %s\n", id)
	}
	return rep.err
}

func explain(ctx context.Context, client *indexer.Client, o options, agentID, onlyControl string, out io.Writer) error {

	rep := &report{w: out}

	var hp struct {
		Found  bool                `json:"found"`
		Source hostprofile.Profile `json:"_source"`
	}
	err := client.Do(ctx, http.MethodGet, "/"+url.PathEscape(o.hostIndex)+"/_doc/"+url.PathEscape(agentID), nil, &hp)
	var e *indexer.Error
	if errors.As(err, &e) && e.Status == http.StatusNotFound || err == nil && !hp.Found {
		return fmt.Errorf("agent %s has no host profile yet; the engine writes it on its next pass", agentID)
	}
	if err != nil {
		return err
	}

	config, err := params.Load(ctx, client, o.configIndex)
	if errors.Is(err, params.ErrNotSaved) {
		config, err = params.Default(), nil
	}
	if err != nil {
		return err
	}
	custom, err := params.LoadProfiles(ctx, client, o.configIndex)
	if err != nil {
		rep.printf("warning: %v\n", err)
	}
	config.UseInventoryTypes(map[string]string{agentID: hp.Source.OS.Platform})
	config.UseProfiles(custom)
	config.UseHostFacts(map[string]catalog.HostFacts{agentID: hp.Source.Facts()})

	f := hp.Source.Facts()
	rep.printf("agent     %s %s\n", agentID, f.Hostname)
	rep.printf("deduced   %s, %s, services: %s\n", or(f.Distro, "unknown distro"), f.Role, or(strings.Join(f.Services, " "), "none"))
	var names []string
	for _, p := range config.MatchedProfiles(agentID) {
		names = append(names, p.ID+" ("+p.Layer+")")
	}
	rep.printf("profiles  %s\n\n", or(strings.Join(names, ", "), "none"))

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	table := &report{w: w}
	table.printf("CONTROL\tPARAMETER\tVALUE\tFROM\n")
	for _, c := range catalog.Controls() {
		if onlyControl != "" && c.Control != onlyControl {
			continue
		}
		for _, paramID := range sortedKeys(c.Parameters) {
			if !catalog.IsAgentLevel(c.Control, paramID) {
				continue
			}
			r, ok := config.Explain(agentID, c.Control, paramID)
			if !ok || r.Value == nil {
				table.printf("%s\t%s\t-\tnot set\n", c.Control, paramID)
				continue
			}
			var from []string
			for _, s := range r.Sources {
				from = append(from, s.String())
			}
			table.printf("%s\t%s\t%s\t%s\n", c.Control, paramID, shortValue(r.Value, r.Mode), strings.Join(from, ", "))
		}
	}
	if table.err != nil {
		return table.err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return rep.err
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

type report struct {
	w   io.Writer
	err error
}

func (r *report) printf(format string, args ...any) {
	if r.err == nil {
		_, r.err = fmt.Fprintf(r.w, format, args...)
	}
}

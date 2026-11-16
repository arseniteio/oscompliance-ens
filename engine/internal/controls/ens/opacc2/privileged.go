package opacc2

import (
	"fmt"
	"strconv"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

func privilegedAccounts(idx accountIndex, groups []string, grants []fact.SudoGrant) (privileged map[string][]string, unresolved []string) {

	privileged = map[string][]string{}
	add := func(name, via string) {
		privileged[name] = append(privileged[name], via)
	}

	for _, g := range groups {
		for _, name := range idx.members(g) {
			add(name, "group "+g)
		}
	}

	for _, grant := range grants {

		via := fmt.Sprintf("sudoers %s:%d", grant.File, grant.Line)

		switch grant.SubjectKind {
		case "user":
			if grant.Subject != "root" {
				add(grant.Subject, via)
			}
		case "uid":
			uid, err := strconv.Atoi(grant.Subject)
			name, ok := idx.byUID[uid]
			if err != nil || !ok {
				unresolved = append(unresolved, "#"+grant.Subject)
				continue
			}
			if name != "root" {
				add(name, via)
			}
		case "group", "gid":
			group := grant.Subject
			if grant.SubjectKind == "gid" {
				gid, err := strconv.Atoi(grant.Subject)
				name, ok := idx.groupByGID[gid]
				if err != nil || !ok {
					unresolved = append(unresolved, "%#"+grant.Subject)
					continue
				}
				group = name
			}
			if _, ok := idx.groupGID[group]; !ok {
				unresolved = append(unresolved, "%"+group)
				continue
			}
			for _, name := range idx.members(group) {
				if name != "root" {
					add(name, via+" via %"+group)
				}
			}
		}
	}

	return privileged, unresolved
}

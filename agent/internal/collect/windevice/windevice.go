package windevice

import (
	_ "embed"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed device.ps1
var script string

type volume struct {
	Drive      string `json:"drive"`
	Protection int    `json:"protection"`
	Method     int    `json:"method"`
}

type output struct {
	Chassis           int      `json:"chassis"`
	Graphical         bool     `json:"graphical"`
	InactivityTimeout *int     `json:"inactivity_timeout"`
	SystemDrive       string   `json:"system_drive"`
	BitLocker         string   `json:"bitlocker"`
	BitLockerError    string   `json:"bitlocker_error"`
	Volumes           []volume `json:"volumes"`
	Resolvers         []string `json:"resolvers"`
	CPUs              int      `json:"cpus"`
	Load              int      `json:"load"`
	Memory            int      `json:"memory"`
}

// SMBIOS chassis types of laptops, notebooks, tablets and convertibles.
var portable = []int{8, 9, 10, 11, 14, 30, 31, 32}

const protectionOn = 1

func Collect(e *emit.Emitter, run winps.Runner) error {

	s := fact.DeviceSecurity{Envelope: e.Envelope(fact.DeviceSecurityFact), Status: fact.SourceRead, Resolvers: []string{}, SynCookies: true}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}
	if out.BitLocker == "error" {
		s.Status, s.Error = fact.SourceError, "BitLocker: "+out.BitLockerError
		return e.Emit(s)
	}

	s.ChassisType, s.Portable, s.Graphical = out.Chassis, slices.Contains(portable, out.Chassis), out.Graphical
	if out.InactivityTimeout != nil {
		enabled := *out.InactivityTimeout > 0
		s.IdleDelay, s.LockEnabled = out.InactivityTimeout, &enabled
		none := 0
		s.LockDelay = &none
	}
	s.RootDevice = out.SystemDrive
	s.RootEncrypted = slices.ContainsFunc(out.Volumes, func(v volume) bool {
		return strings.EqualFold(v.Drive, out.SystemDrive) && v.Protection == protectionOn
	})
	if out.Resolvers != nil {
		s.Resolvers = out.Resolvers
	}
	s.CPUs, s.LoadPercent, s.MemoryPercent = out.CPUs, out.Load, out.Memory

	return e.Emit(s)
}

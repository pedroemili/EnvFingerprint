package collector

import (
	"sort"

	"github.com/envfingerprint/envfingerprint/internal/model"
	"github.com/envfingerprint/envfingerprint/internal/redact"
)

// variablesCollector reads ONLY the variables explicitly declared by the
// project rules (required + compareValues + sensitive). It never enumerates
// the process environment and never reads .env files.
type variablesCollector struct {
	env        Env
	declared   map[string]bool // required ∪ compareValues ∪ sensitive
	compareSet map[string]bool
	classifier redact.Classifier
}

func (c variablesCollector) Name() string { return "variables" }

func (c variablesCollector) Collect() ([]model.Variable, []Diagnostic) {
	var vars []model.Variable
	for key := range c.declared {
		sensitive := c.classifier.Sensitive(key)
		v := model.Variable{
			Key:       key,
			Sensitive: sensitive,
			Compare:   model.ComparePresence,
		}
		value, ok := c.env.Lookup(key)
		if ok {
			v.State = model.StatePresent
		} else {
			v.State = model.StateAbsent
		}
		// Security: sensitive variables are presence-only — their value is
		// never recorded even if the project asked for compareValues (the
		// rules validator rejects that combination earlier; this and
		// redact.Scrub are defense in depth).
		if ok && !sensitive && c.compareSet[key] {
			v.Compare = model.CompareValue
			v.Value = value
		}
		vars = append(vars, v)
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].Key < vars[j].Key })
	return vars, nil
}

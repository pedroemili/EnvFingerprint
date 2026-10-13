package model

// DiffResult is the machine-readable output of `compare --json` (schema v1).
// See docs/CONTRACTS.md §3.
type DiffResult struct {
	Schema     int      `json:"schema"`
	Equal      bool     `json:"equal"`
	Compatible bool     `json:"compatible"`
	Notes      []string `json:"notes"`
	Changes    []Change `json:"changes"`
}

// Change kinds. "unknown" means the field cannot be compared because the
// information is missing on purpose (e.g. value of a sensitive variable) —
// it is not a difference.
const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"
	ChangeUnknown  = "unknown"
)

// Severity levels. They are assigned from verifiable facts and declared rules
// only; a difference is never promoted to error without a rule backing it.
const (
	SeverityInfo    = "info"    // informational, no known violation
	SeverityWarning = "warning" // potentially problematic, review advised
	SeverityError   = "error"   // explicit violation of a mandatory rule
)

// Change is one difference (or one incomparable field, when Kind is
// ChangeUnknown). A and B hold normalized string values; they must never
// contain sensitive variable values.
type Change struct {
	Path        string `json:"path"` // e.g. "runtimes[go].version"
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Rule        string `json:"rule,omitempty"`   // e.g. "variables.required"
	Advice      string `json:"advice,omitempty"` // grounded recommendation, if any
	A           string `json:"a,omitempty"`
	B           string `json:"b,omitempty"`
}

// LoadDiff decodes a diff result document.
func LoadDiff(data []byte, strict bool) (*DiffResult, error) {
	var d DiffResult
	if err := decodeJSON(data, &d, strict); err != nil {
		return nil, err
	}
	return &d, nil
}

func (d *DiffResult) Validate() error {
	var errs Errors

	if err := checkSchema(d.Schema); err != nil {
		errs = append(errs, errf("schema: %v", err))
	}
	if d.Notes == nil {
		errs = append(errs, "notes: must be an array (use [] when empty)")
	}
	if d.Changes == nil {
		errs = append(errs, "changes: must be an array (use [] when empty)")
	}
	seen := map[string]bool{}
	for i, c := range d.Changes {
		where := errf("changes[%d]", i)
		if c.Path == "" {
			errs = append(errs, errf("%s.path: must not be empty", where))
		}
		if seen[c.Path] {
			errs = append(errs, errf("%s.path: duplicate path %q", where, c.Path))
		}
		seen[c.Path] = true
		switch c.Kind {
		case ChangeAdded:
			if c.B == "" {
				errs = append(errs, errf("%s.b: required when kind is added", where))
			}
		case ChangeRemoved:
			if c.A == "" {
				errs = append(errs, errf("%s.a: required when kind is removed", where))
			}
		case ChangeModified, ChangeUnknown:
		default:
			errs = append(errs, errf("%s.kind: unknown value %q", where, c.Kind))
		}
		switch c.Severity {
		case SeverityInfo, SeverityWarning, SeverityError:
		default:
			errs = append(errs, errf("%s.severity: unknown value %q", where, c.Severity))
		}
		if c.Description == "" {
			errs = append(errs, errf("%s.description: must not be empty", where))
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

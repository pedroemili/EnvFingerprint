package model

// DiffResult is the machine-readable output of `diff --json` (schema v1).
// See docs/CONTRACTS.md §3.
type DiffResult struct {
	Schema     int      `json:"schema"`
	Equal      bool     `json:"equal"`
	Compatible bool     `json:"compatible"`
	Notes      []string `json:"notes"`
	Changes    []Change `json:"changes"`
}

// Change kinds for Change.Kind.
const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"
)

// Change is one differing field. A and B hold normalized string values; the
// producer must never place sensitive variable values here.
type Change struct {
	Path string `json:"path"` // e.g. "runtimes[go].version"
	Kind string `json:"kind"`
	A    string `json:"a,omitempty"`
	B    string `json:"b,omitempty"`
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
	for i, c := range d.Changes {
		where := errf("changes[%d]", i)
		if c.Path == "" {
			errs = append(errs, errf("%s.path: must not be empty", where))
		}
		switch c.Kind {
		case ChangeAdded:
			if c.B == "" {
				errs = append(errs, errf("%s.b: required when kind is added", where))
			}
		case ChangeRemoved:
			if c.A == "" {
				errs = append(errs, errf("%s.a: required when kind is removed", where))
			}
		case ChangeModified:
			// a and b may legitimately be empty strings; nothing to check.
		default:
			errs = append(errs, errf("%s.kind: unknown value %q", where, c.Kind))
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

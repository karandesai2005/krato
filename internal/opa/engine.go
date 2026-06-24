package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

// Violation is a policy match with a severity label and human-readable message.
type Violation struct {
	Severity string
	Msg      string
}

// Engine holds all loaded Rego policies.
type Engine struct {
	policiesDir string
	mu          sync.RWMutex
	modules     map[string]string
}

// NewEngine loads all .rego files from the given directory.
func NewEngine(policiesDir string) (*Engine, error) {
	e := &Engine{
		policiesDir: policiesDir,
		modules:     make(map[string]string),
	}
	if err := e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) load() error {
	modules, count, err := e.readModules()
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.modules = modules
	e.mu.Unlock()

	for name := range modules {
		log.Printf("  loaded policy: %s", name)
	}
	_ = count
	return nil
}

func (e *Engine) readModules() (map[string]string, int, error) {
	entries, err := os.ReadDir(e.policiesDir)
	if err != nil {
		return nil, 0, fmt.Errorf("cant read policies dir: %w", err)
	}

	modules := make(map[string]string)
	count := 0

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".rego") {
			path := filepath.Join(e.policiesDir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, 0, err
			}
			modules[entry.Name()] = string(content)
			count++
		}
	}

	if count == 0 {
		return nil, 0, fmt.Errorf("no .rego files found in %s", e.policiesDir)
	}

	return modules, count, nil
}

// Reload re-reads all .rego files and atomically replaces the loaded modules.
func (e *Engine) Reload() error {
	modules, _, err := e.readModules()
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.modules = modules
	e.mu.Unlock()

	return nil
}

// RuleCount returns the number of loaded .rego policy files.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.modules)
}

// Evaluate runs a query against input and returns matching violations.
func (e *Engine) Evaluate(query string, input map[string]interface{}) ([]Violation, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ctx := context.Background()

	opts := []func(*rego.Rego){
		rego.Query(fmt.Sprintf("data.%s", query)),
		rego.Input(input),
	}

	for filename, content := range e.modules {
		opts = append(opts, rego.Module(filename, content))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, err
	}

	return parseViolations(rs), nil
}

func parseViolations(rs rego.ResultSet) []Violation {
	var violations []Violation

	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case map[string]interface{}:
				// OPA returns violation set as map[jsonEncodedObject]true
				// the key is the JSON-encoded violation, value is always true
				for key := range v {
					var obj map[string]interface{}
					if err := json.Unmarshal([]byte(key), &obj); err != nil {
						continue
					}
					severity, _ := obj["severity"].(string)
					msg, _ := obj["msg"].(string)
					if severity != "" && msg != "" {
						violations = append(violations, Violation{
							Severity: severity,
							Msg:      msg,
						})
					}
				}
			case []interface{}:
				// fallback for array-style results
				for _, item := range v {
					if viol, ok := parseViolationItem(item); ok {
						violations = append(violations, viol)
					}
				}
			}
		}
	}

	return violations
}

func parseViolationItem(item interface{}) (Violation, bool) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return Violation{}, false
	}

	severity, _ := m["severity"].(string)
	msg, _ := m["msg"].(string)
	if severity == "" || msg == "" {
		return Violation{}, false
	}

	return Violation{Severity: severity, Msg: msg}, true
}
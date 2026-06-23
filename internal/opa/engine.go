//Loads all .rego files from your policies folder, 
// exposes one method Evaluate(query, input) 
// that returns a list of violation message

package opa

import (
    "context"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strings"

    "github.com/open-policy-agent/opa/rego"
)

// Engine holds all loaded Rego policies
type Engine struct {
    policiesDir string
    modules     map[string]string
}

// NewEngine loads all .rego files from the given directory
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
    entries, err := os.ReadDir(e.policiesDir)
    if err != nil {
        return fmt.Errorf("cant read policies dir: %w", err)
    }

    count := 0
    for _, entry := range entries {
        if strings.HasSuffix(entry.Name(), ".rego") {
            path := filepath.Join(e.policiesDir, entry.Name())
            content, err := os.ReadFile(path)
            if err != nil {
                return err
            }
            e.modules[entry.Name()] = string(content)
            log.Printf("  loaded policy: %s", entry.Name())
            count++
        }
    }

    if count == 0 {
        return fmt.Errorf("no .rego files found in %s", e.policiesDir)
    }
    return nil
}

// Evaluate runs a query against input and returns denial messages
func (e *Engine) Evaluate(query string, input map[string]interface{}) ([]string, error) {
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

    var messages []string
    for _, result := range rs {
        for _, expr := range result.Expressions {
            switch v := expr.Value.(type) {
            case []interface{}:
                for _, item := range v {
                    if msg, ok := item.(string); ok {
                        messages = append(messages, msg)
                    }
                }
            case map[string]interface{}:
                for msg := range v {
                    messages = append(messages, msg)
                }
            }
        }
    }
    return messages, nil
}
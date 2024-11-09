// scripts/todo/main_test.go

package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestScanForTodos(t *testing.T) {
    // Create a temporary test file
    tmpDir := t.TempDir()
    testFile := filepath.Join(tmpDir, "test.go")
    
    content := `package test

// TODO: This is a test todo
func main() {
    // TODO: Another todo
    fmt.Println("hello")
}
`
    err := os.WriteFile(testFile, []byte(content), 0644)
    if err != nil {
        t.Fatal(err)
    }

    // Run the scanner
    todos, err := scanForTodos(tmpDir)
    if err != nil {
        t.Fatal(err)
    }

    // Check results
    if len(todos) != 2 {
        t.Errorf("Expected 2 TODOs, got %d", len(todos))
    }

    for _, todo := range todos {
        t.Logf("Found TODO in %s at line %d: %s", todo.File, todo.Line, todo.Message)
    }
}

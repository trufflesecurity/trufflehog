// scripts/todo/main.go

package main

import (
    "bufio"
    "fmt"
    "os"
    "path/filepath"
    "regexp"
    "sort"
    "strings"
    "time"
)

// TodoItem represents a single TODO comment in the code
type TodoItem struct {
    File    string
    Line    int
    Message string
    Package string
    Type    string
}

// Extract package name from file path
func getPackageName(filePath string) string {
    if strings.Contains(filePath, "pkg/") {
        parts := strings.Split(filePath, "pkg/")[1]
        return strings.Split(parts, "/")[0]
    }
    return "root"
}

// Categorize TODO type based on content
func getTodoType(message string) string {
    lower := strings.ToLower(message)
    switch {
    case strings.Contains(lower, "fix") || strings.Contains(lower, "bug"):
        return "🐛 Bug Fix"
    case strings.Contains(lower, "add") || strings.Contains(lower, "support"):
        return "✨ Enhancement"
    case strings.Contains(lower, "test"):
        return "🧪 Testing"
    case strings.Contains(lower, "refactor"):
        return "♻️ Refactor"
    case strings.Contains(lower, "doc") || strings.Contains(lower, "review"):
        return "📝 Documentation"
    default:
        return "🔄 General"
    }
}

// Find all TODOs in the codebase
func findTodos(rootDir string) ([]TodoItem, error) {
    var todos []TodoItem
    todoPattern := regexp.MustCompile(`//\s*TODO:(.+)`)

    err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() && (info.Name() == ".git" || info.Name() == "vendor") {
            return filepath.SkipDir
        }

        if !strings.HasSuffix(path, ".go") {
            return nil
        }

        file, err := os.Open(path)
        if err != nil {
            return err
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        lineNum := 0
        for scanner.Scan() {
            lineNum++
            if match := todoPattern.FindStringSubmatch(scanner.Text()); match != nil {
                todo := TodoItem{
                    File:    path,
                    Line:    lineNum,
                    Message: strings.TrimSpace(match[1]),
                    Package: getPackageName(path),
                }
                todo.Type = getTodoType(todo.Message)
                todos = append(todos, todo)
            }
        }
        return scanner.Err()
    })

    return todos, err
}

// Helper to get sorted slice from map keys
func getSortedKeys(m map[string]int) []string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    return keys
}

// Generate the formatted TODO.md file
func generateTodoMd(todos []TodoItem) error {
    file, err := os.Create("TODO.md")
    if err != nil {
        return err
    }
    defer file.Close()

    // Write header with badges
    fmt.Fprintf(file, "# TruffleHog TODOs\n\n")
    fmt.Fprintf(file, "<div align=\"center\">\n\n")
    fmt.Fprintf(file, "![Total](<https://img.shields.io/badge/Total_TODOs-%d-blue>)\n", len(todos))
    fmt.Fprintf(file, "![Last Updated](<https://img.shields.io/badge/Last_Updated-%s-green>)\n\n", 
        time.Now().Format("2006--01--02"))
    fmt.Fprintf(file, "</div>\n\n")

    // Count TODOs by type
    typeCount := make(map[string]int)
    for _, todo := range todos {
        typeCount[todo.Type]++
    }

    // Write summary table
    fmt.Fprintf(file, "## 📊 Summary\n\n")
    fmt.Fprintf(file, "| Type | Count |\n")
    fmt.Fprintf(file, "|------|-------|\n")
    for _, typ := range getSortedKeys(typeCount) {
        fmt.Fprintf(file, "| %s | %d |\n", typ, typeCount[typ])
    }
    fmt.Fprintf(file, "\n---\n\n")

    // Write navigation section
    fmt.Fprintf(file, "## 🗺️ Navigation\n\n")
    fmt.Fprintf(file, "<details>\n<summary>Click to expand</summary>\n\n")
    for _, t := range getSortedKeys(typeCount) {
        anchor := strings.ToLower(strings.ReplaceAll(t[2:], " ", "-"))
        fmt.Fprintf(file, "- [%s](#%s) (%d items)\n", t, anchor, typeCount[t])
    }
    fmt.Fprintf(file, "\n</details>\n\n---\n\n")

    // Write TODOs grouped by type and package
    todosByType := make(map[string][]TodoItem)
    for _, todo := range todos {
        todosByType[todo.Type] = append(todosByType[todo.Type], todo)
    }

    for _, todoType := range getSortedKeys(typeCount) {
        fmt.Fprintf(file, "## %s\n\n", todoType)
        
        // Group by package
        packageTodos := make(map[string][]TodoItem)
        for _, todo := range todosByType[todoType] {
            packageTodos[todo.Package] = append(packageTodos[todo.Package], todo)
        }

        // Write each package section
        for _, pkg := range getSortedKeys(countItems(packageTodos)) {
            fmt.Fprintf(file, "<details>\n")
            fmt.Fprintf(file, "<summary>📦 %s (%d items)</summary>\n\n", pkg, len(packageTodos[pkg]))
            
            for _, todo := range packageTodos[pkg] {
                fileLink := fmt.Sprintf("https://github.com/trufflesecurity/trufflehog/blob/main/%s#L%d", 
                    todo.File, todo.Line)
                filename := filepath.Base(todo.File)
                fmt.Fprintf(file, "- [`%s:%d`](%s): %s\n", filename, todo.Line, fileLink, todo.Message)
            }
            fmt.Fprintf(file, "\n</details>\n\n")
        }
        fmt.Fprintf(file, "---\n\n")
    }

    // Write footer
    fmt.Fprintf(file, "\n<div align=\"center\">\n")
    fmt.Fprintf(file, "Generated by TruffleHog TODO Scanner | %s\n", time.Now().Format("2006-01-02"))
    fmt.Fprintf(file, "</div>\n")

    return nil
}

// Helper to count items in a map of slices
func countItems(m map[string][]TodoItem) map[string]int {
    counts := make(map[string]int)
    for k, v := range m {
        counts[k] = len(v)
    }
    return counts
}

func main() {
    fmt.Println("🔍 Scanning for TODOs...")
    
    todos, err := findTodos(".")
    if err != nil {
        fmt.Printf("❌ Error scanning for TODOs: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("✨ Found %d TODOs\n", len(todos))

    if err := generateTodoMd(todos); err != nil {
        fmt.Printf("❌ Error generating TODO.md: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("✅ Generated TODO.md successfully")
}

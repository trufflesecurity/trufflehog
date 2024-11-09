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
    Package string // For grouping TODOs by package
    Type    string // Bug, Enhancement, etc.
}

// Simple helper to extract package name from file path
func getPackageName(filePath string) string {
    // Handle both pkg/ and root level files
    if strings.Contains(filePath, "pkg/") {
        parts := strings.Split(filePath, "pkg/")[1]
        return strings.Split(parts, "/")[0]
    }
    return "root"
}

// Categorize TODOs based on their message content
func getTodoType(message string) string {
    lower := strings.ToLower(message)
    
    // Common patterns that indicate type
    if strings.Contains(lower, "fix") || strings.Contains(lower, "bug") {
        return "🐛 Bug Fix"
    }
    if strings.Contains(lower, "add") || strings.Contains(lower, "support") {
        return "✨ Enhancement"
    }
    if strings.Contains(lower, "test") {
        return "🧪 Testing"
    }
    if strings.Contains(lower, "refactor") {
        return "♻️ Refactor"
    }
    if strings.Contains(lower, "doc") || strings.Contains(lower, "review") {
        return "📝 Documentation"
    }
    
    return "🔄 General"
}

// Find and parse all TODO comments in the codebase
func findTodos(rootDir string) ([]TodoItem, error) {
    var todos []TodoItem
    
    // Match standard TODO format
    todoPattern := regexp.MustCompile(`//\s*TODO:(.+)`)

    // Walk through all .go files
    err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
        // Skip common directories we don't want to scan
        if info.IsDir() && (info.Name() == ".git" || info.Name() == "vendor") {
            return filepath.SkipDir
        }

        // Only look at Go files
        if !strings.HasSuffix(path, ".go") {
            return nil
        }

        // Read the file
        file, err := os.Open(path)
        if err != nil {
            return err
        }
        defer file.Close()

        // Scan line by line
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

// Create the formatted TODO.md file
func createTodoFile(todos []TodoItem) error {
    file, err := os.Create("TODO.md")
    if err != nil {
        return fmt.Errorf("failed to create TODO.md: %v", err)
    }
    defer file.Close()

    // Group TODOs by type
    typeGroups := make(map[string][]TodoItem)
    for _, todo := range todos {
        typeGroups[todo.Type] = append(typeGroups[todo.Type], todo)
    }

    // Write header
    writeHeader(file, len(todos))

    // Write table of contents
    writeTableOfContents(file, typeGroups)

    // Write each section
    for _, todoType := range getSortedTypes(typeGroups) {
        writeTodoSection(file, todoType, typeGroups[todoType])
    }

    return nil
}

// Write the header section with statistics
func writeHeader(file *os.File, totalTodos int) {
    fmt.Fprintf(file, "# TruffleHog TODOs\n\n")
    fmt.Fprintf(file, "📊 **Statistics**\n")
    fmt.Fprintf(file, "- Total TODOs: %d\n", totalTodos)
    fmt.Fprintf(file, "- Last Updated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
}

// Write the table of contents
func writeTableOfContents(file *os.File, typeGroups map[string][]TodoItem) {
    fmt.Fprintf(file, "## Table of Contents\n")
    
    types := getSortedTypes(typeGroups)
    for _, t := range types {
        anchor := strings.ToLower(strings.ReplaceAll(t[2:], " ", "-"))
        fmt.Fprintf(file, "- [%s](#%s) (%d items)\n", t, anchor, len(typeGroups[t]))
    }
    
    fmt.Fprintf(file, "\n---\n\n")
}

// Write a section for a specific TODO type
func writeTodoSection(file *os.File, todoType string, todos []TodoItem) {
    fmt.Fprintf(file, "## %s\n\n", todoType)

    // Group by package
    pkgGroups := make(map[string][]TodoItem)
    for _, todo := range todos {
        pkgGroups[todo.Package] = append(pkgGroups[todo.Package], todo)
    }

    // Write each package group
    for _, pkg := range getSortedPackages(pkgGroups) {
        fmt.Fprintf(file, "### 📦 %s\n\n", pkg)
        for _, todo := range pkgGroups[pkg] {
            fileLink := fmt.Sprintf("https://github.com/trufflesecurity/trufflehog/blob/main/%s#L%d", 
                todo.File, todo.Line)
            filename := filepath.Base(todo.File)
            fmt.Fprintf(file, "- [`%s:%d`](%s): %s\n", filename, todo.Line, fileLink, todo.Message)
        }
        fmt.Fprintln(file)
    }
}

// Helper to get sorted keys
func getSortedTypes(m map[string][]TodoItem) []string {
    types := make([]string, 0, len(m))
    for t := range m {
        types = append(types, t)
    }
    sort.Strings(types)
    return types
}

func getSortedPackages(m map[string][]TodoItem) []string {
    pkgs := make([]string, 0, len(m))
    for p := range m {
        pkgs = append(pkgs, p)
    }
    sort.Strings(pkgs)
    return pkgs
}

func main() {
    fmt.Println("🔍 Scanning for TODOs...")
    
    todos, err := findTodos(".")
    if err != nil {
        fmt.Printf("❌ Error scanning for TODOs: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("✨ Found %d TODOs\n", len(todos))

    if err := createTodoFile(todos); err != nil {
        fmt.Printf("❌ Error generating TODO.md: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("✅ Generated TODO.md successfully")
}

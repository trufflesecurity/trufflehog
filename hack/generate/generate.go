package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-errors/errors"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app                             = kingpin.New("generate", "Generate is used to write new features.")
	kind                            = app.Arg("kind", "Kind of thing to generate.").Required().Enum("detector")
	name                            = app.Arg("name", "Name of the Source/Detector to generate.").Required().String()
	nameTitle, nameLower, nameUpper string
)

func main() {
	log.SetFlags(log.Lmsgprefix)
	log.SetPrefix("😲 [generate] ")

	kingpin.MustParse(app.Parse(os.Args[1:]))
	nameTitle = strings.Title(*name)
	nameLower = strings.ToLower(*name)
	nameUpper = strings.ToUpper(*name)

	switch *kind {
	case "detector":
		mustWriteTemplates([]templateJob{
			{
				TemplatePath:  "pkg/detectors/heroku/heroku.go",
				WritePath:     filepath.Join(folderPath(), nameLower+".go"),
				ReplaceString: []string{"heroku"},
			},
			{
				TemplatePath:  "pkg/detectors/heroku/heroku_test.go",
				WritePath:     filepath.Join(folderPath(), nameLower+"_test.go"),
				ReplaceString: []string{"heroku"},
			},
		})
		// case "source":
		// 	mustWriteTemplates([]templateJob{
		// 		{
		// 			TemplatePath:  "pkg/sources/filesystem/filesystem.go",
		// 			WritePath:     filepath.Join(folderPath(), nameLower+".go"),
		// 			ReplaceString: []string{"filesystem"},
		// 		},
		// 		{
		// 			TemplatePath:  "pkg/sources/filesystem/filesystem_test.go",
		// 			WritePath:     filepath.Join(folderPath(), nameLower+"_test.go"),
		// 			ReplaceString: []string{"filesystem"},
		// 		},
		// 	})
	}
}

type templateJob struct {
	TemplatePath  string
	WritePath     string
	ReplaceString []string
}

func mustWriteTemplates(jobs []templateJob) {
	log.Printf("Generating %s %s\n", strings.Title(*kind), nameTitle)

	// Make the folder.
	log.Printf("Creating folder %s\n", folderPath())
	err := makeFolder(folderPath())
	if err != nil {
		log.Fatal(err)
	}

	// Write the files from templates.
	for _, job := range jobs {
		tmplBytes, err := os.ReadFile(job.TemplatePath)
		if err != nil {
			log.Fatal(err)
		}
		tmplRaw := string(tmplBytes)

		for _, rplString := range job.ReplaceString {
			tmplRaw = strings.ReplaceAll(tmplRaw, strings.ToLower(rplString), "<<.NameLower>>")
			tmplRaw = strings.ReplaceAll(tmplRaw, strings.Title(rplString), "<<.NameTitle>>")
			tmplRaw = strings.ReplaceAll(tmplRaw, strings.ToUpper(rplString), "<<.NameUpper>>")
		}

		tmpl := template.Must(template.New("main").Delims("<<", ">>").Parse(tmplRaw))

		log.Printf("Writing file %s\n", job.WritePath)
		f, err := os.OpenFile(job.WritePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatal(err)
		}
		err = tmpl.Execute(f, templateData{
			NameTitle: nameTitle,
			NameLower: nameLower,
			NameUpper: nameUpper,
		})
		if err != nil {
			log.Fatal(fmt.Errorf("failed to execute template: %w", err))
		}
	}
}

type templateData struct {
	NameTitle string
	NameLower string
	NameUpper string
}

func folderPath() string {
	return filepath.Join("pkg/", *kind+"s", nameLower)
}

func makeFolder(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return errors.New(err)
		}
		return nil
	}
	return errors.Errorf("%s %s already exists", *kind, *name)
}

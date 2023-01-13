package sources

import "fmt"

var SourceChoices = []string{"Git", "Github", "Gitlab", "Amazon S3", "Filesystem", "Syslog", "CircleCI"}

func Run(source string) {
	fmt.Printf("Configuring %s...\n", source)
}

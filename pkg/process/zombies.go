package process

import (
	"os/exec"
	"runtime"
	"strings"
)

func GetGitProcessList() []string {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("ps", "-eo", "pid,state,command")
	} else {
		cmd = exec.Command("ps", "-eo", "pid,stat,cmd")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(output), "\n")
	var gitProcesses []string
	for _, line := range lines {
		if strings.Contains(line, "git") {
			gitProcesses = append(gitProcesses, line)
		}
	}
	return gitProcesses
}

func DetectGitZombies(before, after []string) []string {
	beforeMap := make(map[string]bool)
	for _, process := range before {
		beforeMap[process] = true
	}

	var zombies []string
	for _, process := range after {
		if !beforeMap[process] {
			fields := strings.Fields(process)
			if len(fields) >= 2 && (fields[1] == "Z" || strings.HasPrefix(fields[1], "Z")) {
				zombies = append(zombies, process)
			}
		}
	}
	return zombies
}

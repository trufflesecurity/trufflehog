package sources

import (
	"strings"
)

// RemoveRepoFromResumeInfo removes the repoURL from the resume info.
func RemoveRepoFromResumeInfo(resumeRepos []string, repoURL string) []string {
	index := -1
	for i, repo := range resumeRepos {
		if repoURL == repo {
			index = i
			break
		}
	}

	if index == -1 {
		// We should never be able to be here. But if we are, it means the resume info never had the repo added.
		// So do nothing.
		return resumeRepos
	}

	// This removes the element at the given index.
	return append(resumeRepos[:index], resumeRepos[index+1:]...)
}

// FilterReposToResume filters the existing repos down to those that are included in the encoded resume info.
// It returns the new slice of repos to be scanned.
// It also returns the difference between the original length of the repos and the new length to use for progress reporting.
// It is required that both the resumeInfo repos and the existing repos are sorted.
func FilterReposToResume(repos []string, resumeInfo string) (reposToScan []string, progressOffsetCount int) {
	if resumeInfo == "" {
		return repos, 0
	}

	resumeInfoSlice := DecodeResumeInfo(resumeInfo)

	// Because this scanner is multithreaded, it is possible that we have scanned a range of repositories
	// with some gaps of unlisted but completed repositories in between the ones in resumeInfo.
	// So we know repositories that have not finished scanning are the ones included in the resumeInfo,
	// and those that come after the last repository in the resumeInfo.
	// However, it is possible that a resumed scan does not include all or even any of the repos within the resumeInfo.
	// In this case, we must ensure we still scan all repos that come after the last found repo in the list.
	lastFoundRepoIndex := -1
	resumeRepoIndex := 0
	for i, repoURL := range repos {
		// If the repoURL is bigger than what we're looking for, move to the next one.
		if repoURL > resumeInfoSlice[resumeRepoIndex] {
			resumeRepoIndex++
		}

		// If we've found all of our repositories end the filter.
		if resumeRepoIndex == len(resumeInfoSlice) {
			break
		}

		// If the repoURL is the one we're looking for, add it and update the lastFoundRepoIndex.
		if repoURL == resumeInfoSlice[resumeRepoIndex] {
			lastFoundRepoIndex = i
			reposToScan = append(reposToScan, repoURL)
		}
	}

	// Append all repos after the last one we've found.
	reposToScan = append(reposToScan, repos[lastFoundRepoIndex+1:]...)
	progressOffsetCount = len(repos) - len(reposToScan)
	return
}

func EncodeResumeInfo(resumeInfoSlice []string) string {
	return strings.Join(resumeInfoSlice, "\t")
}

func DecodeResumeInfo(resumeInfo string) []string {
	// strings.Split will, for an empty string, return []string{""},
	// which is an element, where as when there is no resume info we want an empty slice.
	if resumeInfo == "" {
		return nil
	}
	return strings.Split(resumeInfo, "\t")
}

import shutil, sys, math, string, datetime, argparse, tempfile, os, urlparse, platform
from git import Repo
from github import Github, GithubException

if sys.version_info[0] == 2:
    reload(sys)  
    sys.setdefaultencoding('utf8')

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

countrepos = 0
countforks = 0
totalrepos = 0
procrepos = 0

ignoringforks = ""

ignore_filter = {
    'alpha': [
        'abcdefghijklmnopqrstuvwxyz',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    'numeric': [
        '123456789'
    ]
}

def filter(string):
    for t in ignore_filter:
        for s in ignore_filter[t]:
            if string.find(s) >= 0:
                return None
    return string

def newdir(dir):
    if not os.path.exists(dir):
        try:
            os.makedirs(dir)
            return dir
        except OSError as e:  # Guard against race condition
            print e.errno
            raise
        except Exception:
            raise

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > 20:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ncolors:
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    BOLD = ''
    UNDERLINE = ''

if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
   if platform.system()=='Windows':
       bcolors = ncolors
else:
    bcolors = ncolors

def find_strings(git_url, reponame):
    global procrepos, totalrepos
    procrepos = procrepos + 1
    print "Checking %s (%d/%d)" % (git_url, procrepos, totalrepos)

    project_path = tempfile.mkdtemp()

    Repo.clone_from(git_url, project_path)

    repo = Repo(project_path)

    for remote_branch in repo.remotes.origin.fetch():
        branch_name = str(remote_branch).split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass
     
        prev_commit = None
        for curr_commit in repo.iter_commits():
            if not prev_commit:
                pass
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
                for blob in diff:

                    #print i.a_blob.data_stream.read()
                    try:
                        printableDiff = blob.diff.decode()
                    except UnicodeDecodeError as e:
                        print e
                        continue
                    loggableDiff = printableDiff
                    foundSomething = False
                    lines = blob.diff.decode().split("\n")
                    stringlist = []
                    for line in lines:
                        for word in line.split():
                            base64_strings = get_strings_of_set(word, BASE64_CHARS)
                            hex_strings = get_strings_of_set(word, HEX_CHARS)
                            for string in base64_strings:
                                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                                if b64Entropy > 4.5:
                                    if filter(string):
                                        foundSomething = True
                                        printableDiff = printableDiff.replace(string,
                                                                          bcolors.WARNING + string + bcolors.ENDC)
                                        if string not in stringlist: stringlist.append(string)
                            for string in hex_strings:
                                hexEntropy = shannon_entropy(string, HEX_CHARS)
                                if hexEntropy > 3:
                                    if filter(string):
                                        foundSomething = True
                                        printableDiff = printableDiff.replace(string,
                                                                          bcolors.WARNING + string + bcolors.ENDC)
                                        if string not in stringlist: stringlist.append(string)

                    if foundSomething:
                        commit_time =  datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                        print
                        print(bcolors.OKGREEN + "Date: " + commit_time + bcolors.ENDC)
                        print(bcolors.OKGREEN + "Branch: " + branch_name + bcolors.ENDC)
                        print(bcolors.OKGREEN + "Commit: " + prev_commit.message.rstrip() + bcolors.ENDC)
                        for detection in stringlist:
                            print(bcolors.WARNING + "Detected: " + detection + bcolors.ENDC)

                        try:
                            if args.full_diff:
                                print(printableDiff.encode(sys.stdout.encoding, errors='replace'))
                        except UnicodeDecodeError as e:
                            print e

                        if args.log_dir:
                            newdir(os.path.join(args.log_dir, '%s+%s' % (args.github_user, reponame)))
                            logfile = open(os.path.join(args.log_dir, '%s+%s' % (args.github_user, reponame), '%s-truffleHog.log' % prev_commit.name_rev.replace(' ','_').replace('\\','_').replace('/','_')), 'w+')
                            logfile.write("Date: " + commit_time + "\n")
                            logfile.write("Branch: " + branch_name + "\n")
                            logfile.write("Commit: " + prev_commit.message + "\n")
                            for detection in stringlist:
                                logfile.write("Detection: " + detection + "\n")
                            logfile.write(loggableDiff)
                            logfile.close()

            prev_commit = curr_commit

    try: # This delete will fail in Windows when the repo object does not release its file handles
        shutil.rmtree(project_path)
    except Exception as e:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('git_url', type=str, nargs='?', default=None, help='URL for secret searching')
    parser.add_argument('--github-user', '-u', type=str, help='Github user e.g. \'dxa4481\'')
    parser.add_argument('--log-dir', '-l', type=str, nargs='?', help='Log results to specified directory')
    parser.add_argument('--github-access', '-a', type=str, default='.', help='Log results to specified directory')
    parser.add_argument('--ignore-forks', '-i', action='store_true', help='Don\'t check forked repos')
    parser.add_argument('--full-diff', '-f', action='store_true', help='Print full diffs to screen')

    args = parser.parse_args()


    if args.log_dir:
        newdir(os.path.abspath(args.log_dir))
        args.log_dir = os.path.abspath(args.log_dir)

        print "Logging to %s" % args.log_dir

    if args.github_user:
        if args.github_access:
            g = Github(args.github_access)
        else:
            g = Github()

        if g:
            try:
                repos = g.get_user(args.github_user).get_repos()

                for repo in repos:
                    countrepos = countrepos + 1
                    if repo.fork: countforks = countforks + 1

                if args.ignore_forks:
                    totalrepos = countrepos - countforks
                    print "Total: %d" % totalrepos
                    ignoringforks = " being ignored"
                else:
                    totalrepos = countrepos

                procrepos = 0

                print "\nRepositories in %s: %d (forks: %d%s)" % (
                args.github_user, countrepos, countforks, ignoringforks)

                for repo in repos:
                    if not (repo.fork and args.ignore_forks):
                        find_strings("https://www.github.com/%s/%s.git" % (args.github_user, repo.name), repo.name)

            except GithubException as e:
                print '\nGithub API Error: %s' % e.data['message']
                exit(1)

    if args.git_url:
        filename, file_ext = os.path.splitext(os.path.basename(urlparse.urlparse(args.git_url).path))
        totalrepos = 1
        find_strings(args.git_url, filename)


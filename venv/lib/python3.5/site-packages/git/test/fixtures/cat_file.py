import sys

with open(sys.argv[1]) as fd:
    for line in fd.readlines():
        sys.stdout.write(line)
        sys.stderr.write(line)

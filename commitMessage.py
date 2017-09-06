#!/usr/bin/env python


from truffleHog import truffleHog
import sys


def main():
    with open(sys.argv[1]) as a_file:
        data = a_file.readlines()
    data = [x.strip() for x in data]

    [found, output] = truffleHog.entropy_in_strings(data, "\n".join(data))
    if len(found) > 0:
        print(output)
        print(truffleHog.bcolors.FAIL + 'At least one word in the commit message contains too much entropy. '
                                        'Are there secrets that shouldn\'t be included?' + truffleHog.bcolors.ENDC)
    return found

if __name__ == '__main__':
    failed = main()
    exit(1 if failed else 0)

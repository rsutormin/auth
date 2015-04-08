from __future__ import print_function
import sys

gitcommit = sys.argv[1]
epoch = sys.argv[2]

vermap = {}
with open('versions') as vers:
    for line in vers:
        if line and not line[0] == "#":
            git, ver = line.split()  # split on ws
            vermap[git] = ver

if sys.argv[1] in vermap:
    print(vermap[sys.argv[1]])
else:
    print(epoch + '-' + gitcommit)
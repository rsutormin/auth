import sys
import re

VALID_TAG = re.compile("java\-\d+.\d+.\d+")

if __name__ == "__main__":
    tag = None
    for t in sys.argv[1:]:
        if VALID_TAG.match(t):
            if tag:
                print "Two valid tags for this commit: {} {}".format(tag, t)
                sys.exit(1)
            tag = t
    if tag:
        print tag.split('-')[1]
    else:
        print ''

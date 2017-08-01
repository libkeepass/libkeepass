#!/usr/bin/env python3
from __future__ import print_function
import libkeepass
import getpass
import sys

try:
    filename = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) == 3 else getpass.getpass()
except IndexError:
    print('prettyprint.py <kdbx file name> [password]')
    sys.exit(1)

try:
    with libkeepass.open(filename, password=password) as kdb:
        print(kdb.pretty_print().decode('unicode_escape'))
except Exception as e:
    print('Could not prettyprint KeePass Database %s:\n%s' % (filename, str(e)), file=sys.stderr)
    sys.exit(2)

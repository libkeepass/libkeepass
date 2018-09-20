#!/usr/bin/env python3
from __future__ import print_function
import sys
import getpass
import libkeepass
import libkeepass.utils.merge

try:
    args = sys.argv[1:]
    verbose = 0
    if args[0].startswith('-v'):
        verbose = args[0].count('v')
        args.pop(0)
    filename = args[0]
    filename_other = args[1]
    filename_output = args[2]
except IndexError:
    print('merge.py [-v|-vv] <kdbx dest file name> <kdbx src file name> <output file name>')
    print('    merge src into dest and output to output file')
    sys.exit(1)

try:
    with libkeepass.open(filename, password=getpass.getpass()) as kdb, \
         libkeepass.open(filename_other, password=getpass.getpass()) as kdb_other:
        found = {}
        
        # MM_SYNCHRONIZE is the default, but we explicitly pass it here as an
        # example of how to set the desired mode.
        kdbm = kdb.merge(kdb_other, metadata=True, debug=(verbose>0),
                         mode=libkeepass.utils.merge.KDB4Merge.MM_SYNCHRONIZE)
        with open(filename_output, 'wb') as output:
            kdb.write_to(output)
        
        if verbose > 0:
            if verbose > 1:
                print(kdb.pretty_print().decode('utf-8'))
                print(kdb_other.pretty_print().decode('utf-8'))
            
            # Print merge operations to see what occurred during the merge
            print(kdbm.mm_ops)
except Exception as e:
    import traceback
    print('Could not merge KeePass Databases:\n  %s\n  %s\n%s' % (filename, filename_other, str(e)), file=sys.stderr)
    traceback.print_exc()
    sys.exit(2)


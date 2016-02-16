#!/usr/bin/env python3
import libkeepass
import getpass
import sys

try:
    filename = sys.argv[1]
    entry_title = sys.argv[2]
except IndexError:
    print('query.py <kdbx file name> <entry title>')
    sys.exit(1)

#try:
with libkeepass.open(filename, password=getpass.getpass()) as kdb:
    found = {}
    for entry in kdb.obj_root.findall('.//Group/Entry'):
        uuid = entry.find('./UUID').text
        kv = {string.find('./Key').text : string.find('./Value').text for string in entry.findall('./String')}
        if kv['Title'] == entry_title:
            found[uuid] = kv['Password']

    removed_uuids = {uuid.text for uuid in kdb.obj_root.findall('.//DeletedObject/UUID')}

for password in { found[k] for k in found.keys() if k not in removed_uuids }:
    print(password)
#except Exception as e:
#    print('Could not query KeePass Database %s:\n%s' % (filename, str(e)), file=sys.stderr)
#    sys.exit(2)


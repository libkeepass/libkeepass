#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import os
import getpass
import argparse
import code


import libkeepass
import libkeepass.utils
from libkeepass.utils.merge import KDB4Merge


class OpenKDBXFiles(object):
    ""
    def __init__(self, kdbfiles, keyfiles=[], unprotect=True):
        self.unprotect = unprotect
        self.keyfiles = keyfiles
        if keyfiles:
            raise NotImplementedError("KDB files needing keyfiles are not yet supported.")
        self.kdbfiles = kdbfiles
        self.kdbs = []
    
    def __enter__(self):
        creds_list = []
        prompt = 'Password: '
        for kdbfile in self.kdbfiles:
            maxtries = 3
            crlist = creds_list[:]
            ntry = 0
            while ntry < maxtries:
                try:
                    # If more than one file, show which file
                    if len(self.kdbfiles) > 1:
                        tries_s = ''
                        if ntry > 0:
                            tries_s = ' (try {})'.format(ntry)
                        prompt = '{} Password{}: '.format(kdbfile, tries_s)
                    
                    creds = {}
                    if crlist:
                        creds = crlist.pop()
                    else:
                        # Only increment ntry, when the user actually inputs a
                        # password
                        ntry += 1
                        creds = {'password': getpass.getpass(prompt=prompt)}
                        if self.keyfiles:
                            creds['keyfile'] = self.keyfiles
                    kwargs = creds
                    kwargs['unprotect'] = self.unprotect
                    
                    with libkeepass.open(os.path.expanduser(kdbfile), mode='rb', **kwargs) as kdb:
                        self.kdbs.append(kdb)
                        creds_list.append(creds)
                    break
                except OSError as ex:
                    print(ex)
        else:
            del creds_list
        return self.kdbs
        
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for kdb in self.kdbs:
            kdb.close()


def kdbfile_dump(args):
    kdbfile = args.kdbfile
    kdbxmlfile = args.outfile
    
    pwd = getpass.getpass()
    try:
        with libkeepass.open(os.path.expanduser(kdbfile), password=pwd) as kdb:
            if kdbxmlfile == '-':
                print(kdb.pretty_print(True))
            else:
                with open(kdbxmlfile, 'wb') as wf:
                    wf.write(kdb.pretty_print())
    except OSError as ex:
        print(ex)

def kdbfile_shell(args):
    open_args = {}
    if 'keyfile' in args:
        open_args['keyfile'] = args.keyfile
    if 'passwords' in args:
        open_args['unprotect'] = args.passwords
    with OpenKDBXFiles(args.kdbfiles) as kdbfiles:
        code.interact(local=dict(kdbfiles=kdbfiles))
    return
    
    kdbfiles = []
    creds_list = []
    
    prompt = 'Password: '
    for kdbfile in args.kdbfiles:
        maxtries = 3
        crlist = creds_list[:]
        ntry = 0
        while ntry < maxtries:
            try:
                if len(args.kdbfiles) > 1:
                    tries_s = ''
                    if ntry > 0:
                        tries_s = ' (try {})'.format(ntry)
                    prompt = '{} Password{}: '.format(kdbfile, tries_s)
                
                creds = {}
                if crlist:
                    creds = crlist.pop()
                else:
                    # Only increment ntry, when the user actually inputs a
                    # password
                    ntry += 1
                    creds = {'password': getpass.getpass(prompt=prompt)}
                    if 'keyfile' in args:
                        creds['keyfile'] = args.keyfile
                kwargs = creds
                kwargs['unprotect'] = args.passwords
                
                with libkeepass.open(os.path.expanduser(kdbfile), mode='rb', **kwargs) as kdb:
                    kdb.pretty_print()
                    if isinstance(kdb, libkeepass.kdb3.KDB3File):
                        for g in kdb.groups:
                            print (g['title'], g['group_id'], g['level'], g.get('groups', None), g.get('path', '!'))
                    kdbfiles.append(kdb)
                    creds_list.append(creds)
                break
            except OSError as ex:
                print(ex)
    else:
        del creds_list
        print("Opened kdb files are in the list variable 'kdbfiles'.")
        code.interact(local=dict(kdbfiles=kdbfiles))

def kdbfile_convert4(args):
    kdbinfile = args.kdbinfile
    kdboutfile = args.kdboutfile
    
    pwd = getpass.getpass()
    try:
        with libkeepass.open(os.path.expanduser(kdbinfile), password=pwd) as kdb3:
            assert isinstance(kdb3, libkeepass.kdb3.KDB3File)
            with open(kdboutfile, 'wb') as wf:
                kdb4 = libkeepass.utils.convert_kdb3_to_kdb4(kdb3)
                kdb4.write_to(wf)
            if args.debugfile:
                with open(args.debugfile, 'wb') as wf:
                    wf.write(kdb4.pretty_print())
            if args.debug:
                code.interact(local=dict(kdb3=kdb3,kdb4=kdb4))
    except OSError as ex:
        print(ex)

def kdbfile_merge(args):
    kdbfiles = args.kdbfiles
    kdboutfile = args.kdboutfile
    
    if os.path.exists(kdboutfile):
        raise ValueError("Output file must not exist until I add a prompt for overwriting")
    
    try:
        merge_opts = {"debug": args.mdebug}
        if args.type:
            merge_opts["mode"] = getattr(KDB4Merge, 'MM_'+args.type)
        
        with OpenKDBXFiles(args.kdbfiles) as kdbs:
            for i in range(len(kdbs)):
                kdb = kdbs[i]
                if isinstance(kdb, libkeepass.kdb3.KDB3File):
                    print("Warning: using converted KDB3 file, may get unexpected behavior.", file=sys.stderr, flush=True)
                    kdbs[i] = libkeepass.utils.convert_kdb3_to_kdb4(kdb)
            
            for kdb_src in kdbs[1:]:
                kdbm = kdbs[0].merge(kdb_src, **merge_opts)
                if args.details:
                    print("Merge operations from merging", kdb_src.path)
                    print(kdbm.mm_ops)
            
            with open(kdboutfile, 'wb') as wf:
                kdb.write_to(wf)
            if args.debug:
                code.interact(local=dict(kdb=kdb, kdbs=kdbs))
    except OSError as ex:
        print(ex)

def kdbfile_help(args):
    print("TODO: Add general help here, specify a command to get specific help.", file=sys.stderr, flush=True)

def main(argv):
    parser = argparse.ArgumentParser(description='Manipulate KeePass databases')
    subparsers = parser.add_subparsers(help='sub-command help')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='enable debug mode')
    parser.add_argument('-p', '--passwords', action='store_true', default=False,
                        help='show passwords')
    parser.add_argument('-k', '--keyfile', default=None,
                        help='use keyfile')
    parser.set_defaults(func=kdbfile_help)
    
    dump_sparser = subparsers.add_parser('dump')
    dump_sparser.add_argument('kdbfile', help='keepass database file')
    dump_sparser.add_argument('outfile', default='-', help='dump file')
    dump_sparser.set_defaults(func=kdbfile_dump)
    
    kdbshell_sparser = subparsers.add_parser('kdbshell')
    kdbshell_sparser.add_argument('kdbfiles', nargs='+', help='keepass database files')
    kdbshell_sparser.set_defaults(func=kdbfile_shell)
    
    convert4_sparser = subparsers.add_parser('convert4')
    convert4_sparser.add_argument('--debugfile', action='store',
                                  help='write internal xml to file')
    convert4_sparser.add_argument('kdbinfile', help='keepass v3 database file')
    convert4_sparser.add_argument('kdboutfile', help='output file')
    convert4_sparser.set_defaults(func=kdbfile_convert4)
    
    modes = ('OVERWRITE_IF_NEWER', 'SYNCHRONIZE', 'SYNCHRONIZE_3WAY')
    merge_sparser = subparsers.add_parser('merge')
    merge_sparser.add_argument('-d', '--details', action='store_true', default=False,
                               help='print merge operations')
    merge_sparser.add_argument('--mdebug', action='store_true', default=False,
                               help='print merge debug output')
    merge_sparser.add_argument('-t', '--type', choices=modes, default='SYNCHRONIZE',
                               help='select merge type')
    merge_sparser.add_argument('kdbfiles', metavar='kdbfile', nargs='+',
                               help='keepass database file')
    merge_sparser.add_argument('kdboutfile', help='output file')
    merge_sparser.set_defaults(func=kdbfile_merge)
    
    args = parser.parse_args()
    try:
        args.func(args)
    except OSError as ex:
        print(ex)


if __name__ == "__main__":
    main(sys.argv[1:])


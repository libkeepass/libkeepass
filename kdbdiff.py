#!/usr/bin/python

import sys
import argparse
import getpass

try:
    import libkeepass
    from libkeepass.utils.convert import convert_kdb3_to_kxml4
    # The etree module from libkeepass should always be used, otherwise an
    # element created by one module could be operated on by another module
    # which can cause bugs.
    from libkeepass.kdb4 import etree as ET
except ImportError, e:
    import warnings
    import xml.etree.ElementTree as ET
    libkeepass = None
    warnings.warn("Failed to load libkeepass module, diffing only available for xml files: %s"%str(e), RuntimeWarning)


def kp_partition_els(els1, els2, func):
    "partition elements into (only in els1, in both els1 and els2, only in els2)"
    elm1 = dict(zip(map(func, els1), els1))
    elm2 = dict(zip(map(func, els2), els2))
    l, c, r = ([], [], [])
    for k, el in elm1.items():
        if k in elm2:
            c.append((el, elm2[k]))
            elm2.pop(k)
        else:
            l.append(el)
    else:
        r = elm2.values()
    return (l, c, r)


class KXML4Differ(object):
    "Do diffing based on entry name and group, rather than UUID"
    def __init__(self):
        pass
    
    def main(self, args=None):
        self.args = args
        f1, f2 = args.file1, args.file2
        
        doc1, doc2 = self.convert_kxml(f1), self.convert_kxml(f2)
        self.diff_xml(doc1, doc2)
    
    @classmethod
    def convert_kxml(cls, kfile):
        "If kfile is not raw xml, assume a kdb file and extract the xml."
        start = kfile.read(32)
        kfile.seek(0)
        
        if start == b"<?xml version='1.0' encoding='ut":
            doc = ET.parse(kfile)
            root = doc.getroot()
            if root.tag == 'pwlist':
                # Given a kxml v1 file
                raise NotImplementedError("Use diff1 command to diff kxml v1 files: %s"%kfile)
            elif root.tag == 'KeePassFile':
                # Given a kxml v2 file
                return doc
            else:
                raise RuntimeError('Unknown xml file format: %s (%s)'%(kfile, root.tag))
        else:
            if not libkeepass:
                raise RuntimeError("libkeepass module not found, can not open keepass databases")
            
            try:
                pwd = getpass.getpass()
                kdb = libkeepass.open_stream(kfile, password=pwd)
                if isinstance(kdb, libkeepass.kdb3.KDB3File):
                    return libkeepass.utils.convert.convert_kdb3_to_kxml4(kdb)
                elif isinstance(kdb, libkeepass.kdb4.KDB4File):
                    kdb.unprotect()
                    return kdb.obj_root
                else:
                    raise NotImplementedError("type %s"%type(kdb))
            except libkeepass.UnknownKDBError:
                raise RuntimeError("file %s is not kxml or kdb formatted."%kfile)
    
    def diff_xml(self, doc1, doc2):
        root1 = doc1.find('Root')
        root2 = doc2.find('Root')
        self.diff_xml_group(root1, root2)
    
    def diff_xml_group(self, g1, g2, path=None):
        path = path or []
        grps1 = g1.findall('./Group')
        grps2 = g2.findall('./Group')
        kfunc = lambda el: el.find('./Name').text
        grps_sub, grps_com, grps_add = kp_partition_els(grps1, grps2, kfunc)
        grps_com.sort(key=lambda elpair: kfunc(elpair[0]))
        
        bwrite_title = False
        if grps_sub or grps_add:
            print('/'.join(path)+':')
            bwrite_title = True
            for gn in sorted(grps_sub, key=kfunc):
                print('-@'+kfunc(gn))
            for gn in sorted(grps_add, key=kfunc):
                print('+@'+kfunc(gn))
            print()
        
        ents1 = g1.findall('./Entry')
        ents2 = g2.findall('./Entry')
        kfunc = lambda el: el.find("./String[Key='Title']/Value").text
        pfunc = lambda el: el.find("./String[Key='Password']/Value").text
        ents_sub, ents_com, ents_add = kp_partition_els(ents1, ents2, kfunc)
        
        printed = bool(ents_sub or ents_add)
        if ents_sub or ents_add:
            if not bwrite_title:
                print('/'.join(path)+':')
                bwrite_title = True
            for en in sorted(ents_sub, key=kfunc):
                print('-'+kfunc(en)+(self.args.passwords and ' < %r >'%pfunc(en) or ''))
            for en in sorted(ents_add, key=kfunc):
                print('+'+kfunc(en)+(self.args.passwords and ' < %r >'%pfunc(en) or ''))
        for en1, en2 in ents_com:
            p1, p2 = pfunc(en1), pfunc(en2)
            if p1 != p2:
                if not bwrite_title:
                    print('/'.join(path)+':')
                    bwrite_title = True
                print('p'+kfunc(en1))
                if self.args.passwords:
                    print('p < %r != %r >'%(p1, p2))
                printed = True
        if printed:
            print()
        
        for grp1, grp2 in grps_com:
            self.diff_xml_group(grp1, grp2, path[:] + [grp1.find('./Name').text])


def main(argv=[]):
    "Diff two keepass xml exports or keepass databases"
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument('-p', '--passwords', action='store_true', default=False,
                help='show passwords')
    parser.add_argument('file1', type=argparse.FileType('rb'),
                  help='first keepass2 xml or KDB v3/v4 file')
    parser.add_argument('file2', type=argparse.FileType('rb'),
                  help='second keepass2 xml or KDB v3/v4 file')
    parser.set_defaults(func=KXML4Differ().main)
    
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main(sys.argv[1:])

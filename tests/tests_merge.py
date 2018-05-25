# -*- coding: utf-8 -*-
import os
import sys
import datetime
import unittest
import warnings
import copy

import libkeepass
import libkeepass.common
import libkeepass.kdb4
import libkeepass.kdb3
import libkeepass.utils.merge
import libkeepass.utils.check
import six
import lxml.etree

from . import get_datafile
from libkeepass.utils.merge import get_pw_path


# created with KeePass 2.32 on linux
# common ancestor
kdbf_t0 = get_datafile('sample_merge-t0.kdbx')
kdbf_t1 = get_datafile('sample_merge-t0-t1.kdbx')
kdbf_t2 = get_datafile('sample_merge-t0-t2.kdbx')


def pretty_print_xml(el):
    return lxml.etree.tostring(el, pretty_print=True, encoding='utf-8', standalone=True)

class TestKDB4UUIDMergeTrivial(unittest.TestCase):
    def test_merge_self(self):
        """Test direct KDB4Reader class usage"""
        with libkeepass.open(kdbf_t0, password="qwerty") as kdb_dest, \
             libkeepass.open(kdbf_t0, password="qwerty") as kdb_src:
            kdbm = libkeepass.utils.merge.KDB4UUIDMerge(kdb_dest, kdb_src, debug=False)
            kdbm.merge()
            # Merging file into itself, should have no effect
            self.assertEqual(kdb_dest.pretty_print(), kdb_src.pretty_print())
            
            # Check using KDBEqual with all checks on
            eq = libkeepass.utils.check.KDBEqual(metadata=True, history=True, ignore_attrs=False, ignore_times=True)
            is_eq = eq.equal(kdb_dest, kdb_src)
            self.assertTrue(is_eq, msg="KDB not equal: %r"%(eq.error.msg,))
    
    def test_merge_t0_into_t1(self):
        with libkeepass.open(kdbf_t1, password="qwerty") as kdb_orig, \
             libkeepass.open(kdbf_t1, password="qwerty") as kdb_dest, \
             libkeepass.open(kdbf_t0, password="qwerty") as kdb_src:
            dest_kdbxml_orig = kdb_dest.pretty_print()
            kdbm = libkeepass.utils.merge.KDB4UUIDMerge(kdb_dest, kdb_src, debug=False)
            kdbm.merge()
            # Merging ancestor into decendant should have no effect
            self.assertEqual(kdb_dest.pretty_print(), dest_kdbxml_orig)
            
            # Check using KDBEqual with all checks on
            eq = libkeepass.utils.check.KDBEqual(metadata=True, history=True, ignore_attrs=False)
            is_eq = eq.equal(kdb_dest, kdb_orig)
            self.assertTrue(is_eq, msg="KDB not equal: %r"%(eq.error.msg,))


class TestKDB4UUIDMergeT1(unittest.TestCase):
    def setUp(self):
        self.kdb_dest = libkeepass.open(kdbf_t0, password="qwerty", unprotect=True)
        self.kdb_src  = libkeepass.open(kdbf_t1, password="qwerty", unprotect=True)
    
    def tearDown(self):
        self.kdb_dest.close()
        self.kdb_src.close()
    
    def test_merge_t1_into_t0(self):
        "Test merging t1 into t0, which should change t0 into t1."
        kdb_dest = self.kdb_dest
        kdb_src = self.kdb_src
        
        kdbm = libkeepass.utils.merge.KDB4UUIDMerge(kdb_dest, kdb_src, debug=False)
        kdbm.merge()
        
        eq = libkeepass.utils.check.KDBEqual()
        is_eq = eq.equal(kdb_dest, kdb_src)
        self.assertTrue(is_eq, msg="KDB not equal: %r"%(eq.error.msg,))
        
        # Add a char to first Entry uuid, and verify that we catch the mismatch
        entry = kdb_dest.obj_root.find('.//Entry')
        uuid = entry.UUID.text
        entry.UUID._setText(uuid + '!')
        is_eq = eq.equal(kdb_dest, kdb_src)
        self.assertFalse(is_eq, msg="KDB not equal: %r"%(eq.error.msg,))
        self.assertEqual(list(eq.error.vals[0])[0], uuid+'!')
        self.assertEqual(list(eq.error.vals[1])[0], uuid)

    def test_merge_protection(self):
        "Test merging when one has protection on and the other off"
        eq = libkeepass.utils.check.KDBEqual()
        kdb_dest = self.kdb_dest
        kdb_src = self.kdb_src
        kdb_src.protect()
        
        kdbm = libkeepass.utils.merge.KDB4UUIDMerge(kdb_dest, kdb_src, debug=False)
        kdbm.merge()
        
        # Equal fails because src is protected and dest is not, so the password
        # values for src will be encrypted and thus compare differently to the
        # plain text ones in dest.
        is_eq = eq.equal(kdb_dest, kdb_src)
        self.assertFalse(is_eq, msg="KDB not equal: %r"%(eq.error.msg,))
        
        # Not equal should success because the passwords in src are plain text,
        # and so should match dest.  The ProtectedValue will be different, but
        # we are ignoring differences in attributes.
        kdb_src.unprotect()
        is_eq = eq.equal(kdb_dest, kdb_src)
        self.assertTrue(is_eq, msg="KDB not equal: %r"%(eq.error.msg,))


class TestKDB4UUIDMergeT1T2(unittest.TestCase):
    def setUp(self):
        self.kdb_dest = libkeepass.open(kdbf_t1, password="qwerty")
        self.kdb_src  = libkeepass.open(kdbf_t2, password="qwerty")
    
    def tearDown(self):
        self.kdb_dest.close()
        self.kdb_src.close()
    
    def test_merge_t2_into_t1(self):
        "Test merging t2 into t1."
        eq = libkeepass.utils.check.KDBEqual(ignore_times=True)
        kdb_dest = self.kdb_dest
        kdb_src = self.kdb_src
        
        # Save copies of these entries in case they get modified, so we can use
        # then to compare with later
        uuid = 'spHmZwBbGUuqvbi/mVCknw=='
        prev_edest = copy.deepcopy(kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid))
        uuid = 'lG18b6Y1DUyp9bKzoFTBfA=='
        prev_edest2 = copy.deepcopy(kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid))
        
        kdbm = libkeepass.utils.merge.KDB4UUIDMerge(kdb_dest, kdb_src, debug=False)
        kdbm.merge()
        
        # Added entry
        uuid = 'A799Cwgh00GKnC96fmzrTA=='
        edest = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid)
        esrc = kdb_src.obj_root.find(".//Entry[UUID='%s']"%uuid)
        self.assertIsNotNone(edest, msg="UUID %s not found in dest"%uuid)
        self.assertTrue(eq.entry_equal(edest, esrc), msg="Entry not equal: %s"%eq.error.msg)
        
        # Merge differing entry
        uuid = 'spHmZwBbGUuqvbi/mVCknw=='
        dest_pass = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid).find("./String[Key='Password']").Value
        src_pass = kdb_src.obj_root.find(".//Entry[UUID='%s']"%uuid).find("./String[Key='Password']").Value
        self.assertEqual(dest_pass, src_pass)
        
        lasthist_edest = None
        for lasthist_edest in kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid).History.getchildren():
            if lasthist_edest.Times.LastModificationTime == prev_edest.Times.LastModificationTime:
                break
        else:
            # Didn't find history entry with matching last modified
            self.assertTrue(False, msg="No matching history entry found for %s with last modified at %s"%(uuid, prev_edest.Times.LastModificationTime))
        is_eq = eq.entry_equal(prev_edest, lasthist_edest)
        self.assertTrue(is_eq, msg="KDB entry not equal: %r"%(eq.error.msg,))
        
        src_locchngd = kdb_src.obj_root.find(".//Entry[UUID='%s']"%uuid).Times.LocationChanged
        dest_locchngd = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid).Times.LocationChanged
        self.assertEqual(dest_locchngd, src_locchngd)
        
        # Moved Entry
        uuid = 'spHmZwBbGUuqvbi/mVCknw=='
        edest = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid)
        self.assertEqual('/sample_merge/Internet/Samples/Sample Entry (History)', get_pw_path(edest))
        
        src_locchngd = kdb_src.obj_root.find(".//Entry[UUID='%s']"%uuid).Times.LocationChanged
        dest_locchngd = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid).Times.LocationChanged
        self.assertEqual(dest_locchngd, src_locchngd)
        
        # Moved Group
        uuid = 'znngr4jmiU6+EPU7zWqYNg=='
        edest = kdb_dest.obj_root.find(".//Group[UUID='%s']"%uuid)
        self.assertEqual('/sample_merge/Internet/Samples', get_pw_path(edest))
        
        src_locchngd = kdb_src.obj_root.find(".//Group[UUID='%s']"%uuid).Times.LocationChanged
        dest_locchngd = kdb_dest.obj_root.find(".//Group[UUID='%s']"%uuid).Times.LocationChanged
        self.assertEqual(dest_locchngd, src_locchngd)
        
        # Add new string key to entry and move entry
        uuid = 'lG18b6Y1DUyp9bKzoFTBfA=='
        sedest = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid).find("./String[Key='PIN']")
        self.assertIsNotNone(sedest, msg="UUID %s not found in dest"%uuid)
        self.assertEqual('0000', sedest.Value.text)
        
        edest = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid)
        self.assertEqual('/sample_merge/Homebanking/Sample Entry #2', get_pw_path(edest))
        
        lasthist_edest = None
        for lasthist_edest in kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid).History.getchildren():
            if lasthist_edest.Times.LastModificationTime == prev_edest2.Times.LastModificationTime:
                break
        else:
            # Didn't find history entry with matching last modified
            self.assertTrue(False, msg="No matching history entry found for %s with last modified at %s"%(uuid, prev_edest2.Times.LastModificationTime))
        is_eq = eq.entry_equal(prev_edest2, lasthist_edest)
        self.assertTrue(is_eq, msg="KDB entry not equal: %r"%(eq.error.msg,))
        
        # Moved entry
        uuid = 'Wi5/5yOMVUya/O4RXGbfVg=='
        edest = kdb_dest.obj_root.find(".//Entry[UUID='%s']"%uuid)
        self.assertEqual('/sample_merge/Homebanking/Sample Entry #3', get_pw_path(edest))


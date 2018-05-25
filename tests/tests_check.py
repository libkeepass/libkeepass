# -*- coding: utf-8 -*-
import os
import sys
import datetime
import unittest
import warnings
import copy

import libkeepass.utils.check
import six
import lxml.etree
import lxml.objectify

from . import get_datafile

xmlfile = get_datafile('sample_merge-t0-t1.kdbxml')


def pretty_print_xml(el):
    return lxml.etree.tostring(el, pretty_print=True, encoding='utf-8', standalone=True)

class TestKDB4UUIDCheck(unittest.TestCase):
    def setUp(self):
        xmlf = open(get_datafile(xmlfile))
        
        self.eq = libkeepass.utils.check.KDBEqual()
        self.root = lxml.objectify.parse(xmlf).getroot()
        xmlf.seek(0)
        self.rootmod = lxml.objectify.parse(xmlf).getroot()
        self.entry = self.root.find(".//Entry")
        self.group = self.root.find(".//Group")
        
        xmlf.close()
    
    def test_trivial(self):
        self.assertTrue(self.eq.tree_equal(self.root, self.rootmod))


class TestKDB4UUIDCheck_root_equal(TestKDB4UUIDCheck):
    def test_trivial(self):
        self.assertTrue(self.eq.root_equal(self.root.Root, self.rootmod.Root))
    
    def test_two_entry_changes(self):
        entry2 = self.root.findall(".//Entry")[1]
        
        e = entry2.find("./String[Key='Title']")
        e.Value._setText('change 2')
        self.assertFalse(self.eq.root_equal(self.root.Root, self.rootmod.Root))
        
        e = self.entry.find("./String[Key='Title']")
        e.Value._setText('change 1')
        self.assertFalse(self.eq.root_equal(self.root.Root, self.rootmod.Root))


class TestKDB4UUIDCheck_elem_tree_equal(TestKDB4UUIDCheck):
    def test_trivial(self):
        self.assertTrue(self.eq.elem_tree_equal(self.root, self.rootmod))
    
    def test_attrib(self):
        val = self.entry.find("./String[Key='Password']").Value
        val.attrib.clear()
        self.eq.ignore_attrs = False
        self.assertFalse(self.eq.elem_tree_equal(self.root, self.rootmod))
        
        self.eq.ignore_attrs = True
        self.assertTrue(self.eq.elem_tree_equal(self.root, self.rootmod))
        
        val.set('newattr', 'someval')
        self.assertTrue(self.eq.elem_tree_equal(self.root, self.rootmod))
    
    def test_reorder(self):
        # Extra password at the end
        s = self.entry.find("./String[Key='Password']")
        self.entry.append(copy.deepcopy(s))
        self.assertFalse(self.eq.elem_tree_equal(self.root, self.rootmod))
        
        # Remove original password, effectively moving password to last element of entry
        self.entry.remove(s)
        self.assertTrue(self.eq.elem_tree_equal(self.root, self.rootmod))
        
        s = self.entry.find("./Times/LastModificationTime")
        sp = s.getparent()
        sp.remove(s)
        sp.append(s)
        self.assertTrue(self.eq.elem_tree_equal(self.root, self.rootmod))

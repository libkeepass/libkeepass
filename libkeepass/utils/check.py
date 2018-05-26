# -*- coding: utf-8 -*-

import lxml.etree
import lxml.objectify


class KDBEqualError(object):
    def __init__(self, *args, msg=''):
        self.vals = args
        self.msg = msg


def elem_tree_nequal(el_a, el_b, ignore_elements=tuple(), ignore_attrs=True):
    "Return False if element trees are equal ignoring reordering, otherwise an return an error."
    error = None
    
    if (el_a.text or '').strip() != (el_b.text or '').strip():
        error = KDBEqualError(el_a, el_b, msg="Text of element differ: %s != %s"%(el_a.text, el_b.text))
        return error
    
    if not ignore_attrs and el_a.attrib != el_b.attrib:
        error = KDBEqualError(el_a, el_b, msg="Attributes differ: %s != %s"%(el_a.attrib, el_b.attrib))
        return error
    
    chld_as = el_a.getchildren()
    
    tagmap = {}
    for chld_a in chld_as:
        if chld_a.tag in ignore_elements:
            continue
        
        if chld_a.tag not in tagmap:
            chld_bs = el_b.findall('./%s'%chld_a.tag)
            tagmap.setdefault(chld_a.tag, chld_bs)
        
        chld_bs = tagmap[chld_a.tag]
        for i, chld_b in enumerate(chld_bs):
            if not elem_tree_nequal(chld_a, chld_b, ignore_elements=ignore_elements, ignore_attrs=ignore_attrs):
                chld_bs.pop(i)
                break
        else:
            error = KDBEqualError(chld_a, el_b, msg="Did not find matching %s in %s on right side"%(chld_a.tag, el_b.tag))
            return error
    else:
        # If any values left in tagmap, then there were elements in B that
        # were not in A, so return False.
        any_left = any(filter(lambda v: bool(v), tagmap.values()))
        if any_left:
            error = KDBEqualError(any_left, el_b, msg="Extra elements on the left side. {%s}"%(any_left))
            return error
    
    return False


def elem_tree_equal(el_a, el_b, **kwargs):
    "Return True if element trees are equal ignoring reordering."
    return not elem_tree_nequal(el_a, el_b, **kwargs)


class KDBEqual(object):
    def __init__(self, metadata=False, ignore_times=False, history=False,
                 deleted_objects=True, ignore_attrs=True, ignore_access_time=True):
        self.metadata = metadata
        self.ignore_times = ignore_times
        self.history = history
        self.deleted_objects = deleted_objects
        self.ignore_attrs = ignore_attrs
        self.ignore_access_time = ignore_access_time
        
        self.error = KDBEqualError()
    
    def equal(self, kdb_a, kdb_b):
        "Return true if two kdb files are equal ignoring reordering"
        return self.tree_equal(kdb_a.obj_root, kdb_b.obj_root)

    def tree_equal(self, tree_a, tree_b):
        if self.metadata:
            meta_a, meta_b = tree_a.Meta, tree_b.Meta
            if not self.metadata_equal(meta_a, meta_b):
                self.error.msg = "Metas differ: " + self.error.msg
                return False
        
        return self.root_equal(tree_a.Root, tree_b.Root)

    def metadata_equal(self, meta_a, meta_b):
        ignore_elements = ['HeaderHash', 'LastSelectedGroup', 'LastTopVisibleGroup']
        if self.ignore_times:
            for chld in meta_a.getchildren():
                if chld.tag.endswith('Changed'):
                    ignore_elements.append(chld.tag)
        return self.elem_tree_equal(meta_a, meta_b, ignore_elements=ignore_elements)

    def root_equal(self, root_a, root_b):
        uuid_map_a = {}
        uuid_map_b = {}
        
        # Create UUID maps
        for root, uuid_map in ((root_a, uuid_map_a), (root_b, uuid_map_b)):
            for uuid in root.findall(".//*/UUID"):
                puuid = uuid.getparent()
                if puuid.tag not in ('Group', 'Entry'):
                    assert puuid.tag in ('DeletedObject',), puuid.tag
                    continue
                if puuid.getparent().tag == 'History':
                    continue
                assert uuid.text not in uuid_map, uuid.text
                uuid_map[uuid.text] = puuid
        
        # If the set of keys are not equal, then they can't be equal
        if set(uuid_map_a.keys()) != set(uuid_map_b.keys()):
            ldiff = set(uuid_map_a.keys()).difference(set(uuid_map_b.keys()))
            rdiff = set(uuid_map_b.keys()).difference(set(uuid_map_a.keys()))
            self.error = KDBEqualError(ldiff, rdiff, msg="UUID sets do not match. (l=%s, r=%s)"%(ldiff, rdiff))
            return False
        
        for uuid, elem_a in uuid_map_a.items():
            elem_b = uuid_map_b[uuid]
            ret = False
            if elem_a.tag == 'Group':
                ret = self.group_equal(elem_a, elem_b)
            elif elem_a.tag == 'Entry':
                ret = self.entry_equal(elem_a, elem_b)
            else:
                raise Exception("Tag %s has a UUID!?!?"%elem_a.tag)
            
            # A subtest failed
            if not ret:
                return ret
        
        return True

    def group_equal(self, elem_a, elem_b, recursive=False):
        assert elem_a.UUID == elem_b.UUID, (elem_a, elem_b)
        
        ret = self.elem_tree_equal(elem_a, elem_b, ignore_elements=('Times', 'Group', 'Entry'))
        if not ret:
            self.error.msg = "Groups differ [%s]: "%(elem_a.UUID.text) + self.error.msg
            return False
        
        # Error out early if Times don't match
        ret = self.times_equal(elem_a, elem_b)
        if not ret:
            self.error.msg = "Groups differ [%s]: "%(elem_a.UUID.text) + self.error.msg
            return False
        
        uuids_a = elem_a.findall('./Group/UUID')
        uuids_a += elem_a.findall('./Entry/UUID')
        uuids_b = elem_b.findall('./Group/UUID')
        uuids_b += elem_b.findall('./Entry/UUID')
        suuids_a = set(e.text for e in uuids_a)
        suuids_b = set(e.text for e in uuids_b)
        if suuids_a != suuids_b:
            ldiff = suuids_a.difference(suuids_b)
            rdiff = set(suuids_b).difference(suuids_a)
            self.error = KDBEqualError(ldiff, rdiff, msg="UUID sets of sub groups and entries do not match. (l=%s, r=%s)"%(ldiff, rdiff))
            return False
        
        if recursive:
            for e_a, e_b in sorted(zip(uuids_a, uuids_b), key=lambda item: (item[0].text, item[1].text)):
                assert e_a.text == e_b.text, (e_a.text, e_b.text)
                pe_a = e_a.getparent()
                pe_b = e_b.getparent()
                if pe_a.tag == 'Group':
                    ret = self.group_equal(pe_a, pe_b, recursive)
                elif pe_a.tag == 'Entry':
                    ret = self.entry_equal(pe_a, pe_b)
                else:
                    assert False, "There should only be Groups or Entrys here: %s"%pe_a.tag
                
                if not ret:
                    self.error.msg = "Groups differ [%s]: "%(elem_a.UUID.text) + self.error.msg
                    return False
        
        return True

    def entry_equal(self, elem_a, elem_b):
        assert elem_a.UUID == elem_b.UUID, (elem_a, elem_b)
        
        ignore_elements = ('Times',)
        if not self.history:
            ignore_elements += ('History',)
        
        ret = self.elem_tree_equal(elem_a, elem_b, ignore_elements=ignore_elements)
        if not ret:
            self.error.msg = "Entries differ [%s]: "%(elem_a.UUID.text) + self.error.msg
            return False
        
        ret = self.times_equal(elem_a, elem_b)
        if not ret:
            self.error.msg = "Entries differ [%s]: "%(elem_a.UUID.text) + self.error.msg
            return False
        return True

    def times_equal(self, elem_a, elem_b):
        "Given elements with a Times element, return True if they are equal."
        times_a = elem_a.findall('./Times')
        times_b = elem_b.findall('./Times')
        assert len(times_a) == 1, elem_a
        assert len(times_b) == 1, elem_b
        ignore_elements = []
        if self.ignore_access_time:
            ignore_elements = ['LastAccessTime', 'UsageCount']
        if not self.ignore_times:
            if not self.elem_tree_equal(times_a[0], times_b[0], ignore_elements=ignore_elements):
                self.error.msg = "Times differ: " + self.error.msg
                return False
        
        return True

    def elem_tree_equal(self, el_a, el_b, ignore_elements=tuple()):
        "Return True if element trees are equal ignoring reordering."
        ret = elem_tree_nequal(el_a, el_b, ignore_elements=ignore_elements, ignore_attrs=self.ignore_attrs)
        if ret:
            self.error = ret
            return False
        return True



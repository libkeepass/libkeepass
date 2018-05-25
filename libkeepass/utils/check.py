# -*- coding: utf-8 -*-

import lxml.etree
import lxml.objectify


class KDBEqualError(object):
    def __init__(self, *args, msg=''):
        self.vals = args
        self.msg = msg


class KDBEqual(object):
    def __init__(self, metadata=False, ignore_times=False, history=False,
                 deleted_objects=True, ignore_attrs=True):
        self.metadata = metadata
        self.ignore_times = ignore_times
        self.history = history
        self.deleted_objects = deleted_objects
        self.ignore_attrs = ignore_attrs
        
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
        
        groups = elem_a.findall('./Group')
        entrys = elem_a.findall('./Entry')
        
        # Verify that all entries and subgroups of this group are in the other one
        for chld_a in (groups + entrys):
            chld_b = elem_b.findall("./%s[UUID='%s']"%(chld_a.tag, chld_a.UUID.text))
            if chld_b is None:
                self.error = KDBEqualError(chld_a, elem_b, msg="Did not find %s with UUID %s in right side"%(chld_a.tag, chld_a.UUID.text))
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
        if not self.ignore_times:
            if not self.elem_tree_equal(times_a[0], times_b[0]):
                self.error.msg = "Times differ: " + self.error.msg
                return False
        
        return True

    def elem_tree_equal(self, el_a, el_b, ignore_elements=tuple()):
        "Return True if element trees are equal ignoring reordering."
        if (el_a.text or '').strip() != (el_b.text or '').strip():
            return False
        
        if not self.ignore_attrs and el_a.attrib != el_b.attrib:
            self.error = KDBEqualError(el_a, el_b, msg="Attributes differ: %s != %s"%(el_a.attrib, el_b.attrib))
            return False
        
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
                if self.elem_tree_equal(chld_a, chld_b, ignore_elements=ignore_elements):
                    chld_bs.pop(i)
                    break
            else:
                self.error = KDBEqualError(chld_a, el_b, msg="Did not find %s in %s on right side"%(chld_a.tag, el_b.tag))
                return False
        else:
            # If any values left in tagmap, then there were elements in B that
            # were not in A, so return False.
            any_left = any(filter(lambda v: bool(v), tagmap.values()))
            if any_left:
                self.error = KDBEqualError(any_left, el_b, msg="Extra elements on the left side. {%s}"%(any_left))
                return False
        
        return True



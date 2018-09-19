# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import os
import io
from datetime import datetime
from copy import deepcopy

import lxml.etree
import lxml.objectify

from . import parse_timestamp, unparse_timestamp
from .check import elem_tree_equal

debugfile = sys.stderr


def pw_name(el):
    assert el.tag in ('Entry', 'Group'), el
    if el.tag == 'Entry':
        r = el.find("./String[Key='Title']").Value.text
    elif el.tag == 'Group':
        r = el.Name.text
    return r

def get_elem_path(elem, stop_func=lambda el: not el.getparent(), pfunc=lambda el: el.tag):
    comps = []
    while stop_func(elem):
        comps.insert(0, pfunc(elem))
        elem = elem.getparent()
    abspath = []
    if elem is not None and elem.tag == 'Root':
        abspath = ['']
    return '/'.join(abspath+comps)

def get_root_path(elem, **kwargs):
    return get_elem_path(elem, lambda el: (el is not None) and (el.tag != 'Root'), **kwargs)

def get_pw_path(elem):
    "Get path of entry/group where each component is the name of the component"
    return get_root_path(elem, pfunc=pw_name)

def get_uuid_path(elem):
    "Get path of entry/group where each component is the uuid of the component"
    return get_root_path(elem, pfunc=lambda el: el.UUID.text)


class KDBMergeOps(object):
    # Merge Operations
    MOPS_MOVE = 1 # args: entry/group, old path
    MOPS_ADD_GROUP = 2 # args: entry
    MOPS_ADD_ENTRY = 3 # args: group
    MOPS_ADD_PROP = 4 # args: entry/group, property
    MOPS_MOD_PROP = 5 # args: entry/group, old prop, new prop
    MOPS_MOD_META_PROP = 6 #args: meta field, old field value, new field value
    MOPS_DEL_GROUP = 7 # args: deleted group, old path, deletion time
    MOPS_DEL_ENTRY = 8 # args: deleted entry, old path, deletion time
    MOPS_DEL_PROP = 9 # args: entry/group, old field value
    MOPS_ADD_HISTORY = 10 # args: entry/group, history item
    
    def __init__(self):
        self.ops = []
    
    def append(self, op):
        self.ops.append(op)
    
    def __str__(self):
        sio = io.StringIO()
        if not self.ops:
            return u"Merge made no changes\n"
        
        prev_el = None
        print(u"Merge changes:", file=sio)
        for op in self.ops:
            opcode, vals = op[0], op[1:]
            
            if prev_el is None or prev_el != vals[0]:
                # If the header for this element hasn't been printed yet,
                # then print it for certain merge ops.
                if opcode in (self.MOPS_ADD_PROP, self.MOPS_MOD_PROP, self.MOPS_DEL_PROP, self.MOPS_MOD_META_PROP):
                    print(u" ~[{}:{}]{}".format(vals[0].tag, vals[0].UUID.text, get_pw_path(vals[0])), file=sio)
        
            if opcode == self.MOPS_MOVE:
                print(u" >[{}:{}]{}".format(vals[0].tag, vals[0].UUID.text, vals[1]), file=sio)
                print(u"        -> " + get_pw_path(vals[0]), file=sio)
            elif opcode == self.MOPS_ADD_GROUP:
                print(u" +[Group:{}]{}".format(vals[0].UUID.text, get_pw_path(vals[0])), file=sio)
            elif opcode == self.MOPS_ADD_ENTRY:
                print(u" +[Entry:{}]{}".format(vals[0].UUID.text, get_pw_path(vals[0])), file=sio)
            elif opcode == self.MOPS_ADD_PROP:
                if vals[1].tag == 'String':
                    print(u"    +{} = {!r}".format(vals[1].Key.text, vals[1].Value.text), file=sio)
                else:
                    print(u"    +{} = {!r}".format(vals[1].tag, lxml.etree.tostring(vals[1])), file=sio)
            elif opcode == self.MOPS_MOD_PROP:
                oldprop, newprop = vals[1:]
                if oldprop.tag == 'String':
                    print(u"    ~{}: {!r} -> {!r}".format(oldprop.Key.text, oldprop.Value.text, newprop.Value.text), file=sio)
                else:
                    print(u"    ~{}: {!r} -> {!r}".format(oldprop.tag, oldprop.text, newprop.text), file=sio)
            elif opcode == self.MOPS_MOD_META_PROP:
                print(u"    ~{}: {} -> {}".format(*vals[1:]), file=sio)
            elif opcode == self.MOPS_DEL_GROUP:
                print(u" -[Group:{}]{}  <{}>".format(vals[0].UUID.text, vals[1], vals[2]), file=sio)
            elif opcode == self.MOPS_DEL_ENTRY:
                print(u" -[Entry:{}]{}  <{}>".format(vals[0].UUID.text, vals[1], vals[2]), file=sio)
            elif opcode == self.MOPS_DEL_PROP:
                if vals[1].tag == 'String':
                    print(u"    -{} ".format(vals[1].Key.text), file=sio)
                else:
                    print(u"    -{} ".format(vals[1].tag), file=sio)
            elif opcode == self.MOPS_ADD_HISTORY:
                print(u" +[{}]{} Add history {}".format(vals[0].UUID.text, get_pw_path(vals[0]), vals[1].Times.LastModificationTime), file=sio)
                
            else:
                raise Exception("Unknown merge opcode %r"%opcode)
            prev_el = vals[0]
        return sio.getvalue()


class KDBMerge(object):
    "KDB merging base class"
    def merge(kdb_a, kdb_b):
        raise NotImplementedError("merging is unimplemented")

    def _debug(self, *args, **kwargs):
        kwargs.setdefault('file', self.debug)
        print(*args, **kwargs)

    @property
    def debug(self):
        return self.__debug
    
    @debug.setter
    def debug(self, val):
        if val is True:
            val = debugfile
        self.__debug = val


class KDB4Merge(KDBMerge):
    # Merge Modes
    MM_OVERWRITE_EXISTING = 1 # merge source always wins
    MM_KEEP_EXISTING = 2 # merge dest always wins
    MM_OVERWRITE_IF_NEWER = 3 # resolve merge conflicts by assuming the newest wins
    MM_CREATE_NEW_UUIDS = 4 # import groups and entries with new uuids, so
        # merging a database into itself this way will create a bunch of dups
    MM_SYNCHRONIZE = 5 # resolve merge conflicts by assuming the newest wins and do
        # relocations, object deletions, etc...
    MM_SYNCHRONIZE_3WAY = 6 # same as MM_SYNCHRONIZE, but merge at a field level
    MM_FULLAUTO = 7 # assume newest wins
    MM_INTERACTIVE = 8 # ask the user
    MM_DEFAULT = MM_SYNCHRONIZE

    def __init__(self, kdb_dest, kdb_src, metadata=False, mode=MM_DEFAULT,
                       debug=False):
        self.kdb_dest, self.kdb_src = kdb_dest, kdb_src
        self.metadata = metadata
        self.mode = mode
        self.debug = debug
        
        supported_modes = (
            self.MM_OVERWRITE_IF_NEWER,
            self.MM_SYNCHRONIZE,
            self.MM_SYNCHRONIZE_3WAY)
        if mode not in supported_modes:
            raise NotImplementedError("Mode %s is not supported"%mode)
        
        assert self.__class__ != KDB4Merge, "Must use subclass of KDB4Merge"
        
        # All newer entries from kdb_src should overwrite entries in kdb_dest.
        assert hasattr(kdb_dest, 'obj_root'), kdb_dest
        assert hasattr(kdb_src,  'obj_root'), kdb_src
        
        self.mm_ops = KDBMergeOps()

    def merge(self):
        "Merge a KDB4 databases"
        kdb_dest, kdb_src = self.kdb_dest, self.kdb_src
        
        # databases must be unprotected to do a merge
        protected_dest = kdb_dest.is_protected()
        protected_src = kdb_src.is_protected()
        if protected_dest:
            kdb_dest.unprotect()
        if protected_src:
            kdb_src.unprotect()
        
        if self.metadata:
            self._merge_metadata(kdb_dest.obj_root.Meta, kdb_src.obj_root.Meta)
        
        self._merge_roots(kdb_dest.obj_root.Root, kdb_src.obj_root.Root)
        
        # Set protected status back to the way it was before
        if protected_dest:
            kdb_dest.protect()
        if protected_src:
            kdb_src.protect()

    def _merge_metadata(self, mdest, msrc):
        #~ <Generator>KeePass</Generator>
        #~ <DatabaseName>test database</DatabaseName>
        #~ <DatabaseNameChanged>2016-06-04T09:46:34Z</DatabaseNameChanged>
        #~ <DatabaseDescription />
        #~ <DatabaseDescriptionChanged>2016-06-04T09:45:40Z</DatabaseDescriptionChanged>
        #~ <DefaultUserName />
        #~ <DefaultUserNameChanged>2016-06-04T09:45:40Z</DefaultUserNameChanged>
        #~ <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
        #~ <Color />
        #~ <MasterKeyChanged>2016-06-04T09:45:42Z</MasterKeyChanged>
        #~ <MasterKeyChangeRec>-1</MasterKeyChangeRec>
        #~ <MasterKeyChangeForce>-1</MasterKeyChangeForce>
        #~ <MemoryProtection>
                #~ <ProtectTitle>False</ProtectTitle>
                #~ <ProtectUserName>False</ProtectUserName>
                #~ <ProtectPassword>True</ProtectPassword>
                #~ <ProtectURL>False</ProtectURL>
                #~ <ProtectNotes>False</ProtectNotes>
        #~ </MemoryProtection>
        #~ <RecycleBinEnabled>True</RecycleBinEnabled>
        #~ <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
        #~ <RecycleBinChanged>2016-06-04T09:45:40Z</RecycleBinChanged>
        #~ <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
        #~ <EntryTemplatesGroupChanged>2016-06-04T09:45:40Z</EntryTemplatesGroupChanged>
        #~ <HistoryMaxItems>10</HistoryMaxItems>
        #~ <HistoryMaxSize>6291456</HistoryMaxSize>
        #~ <LastSelectedGroup>111SFa2n7QmsNny84dYODg==</LastSelectedGroup>
        #~ <LastTopVisibleGroup>111SFa2n7QmsNny84dYODg==</LastTopVisibleGroup>
        #~ <Binaries />
        #~ <CustomData />
        
        ts_fields = ('DatabaseName', 'DatabaseDescription', 'DefaultUserName',
            'EntryTemplatesGroup')
        for ts_field in ts_fields:
            if parse_timestamp(getattr(mdest, ts_field+'Changed', datetime.utcfromtimestamp(0))) \
             < parse_timestamp(getattr(msrc, ts_field+'Changed')):
                self.mm_ops.append((KDBMergeOps.MOPS_MOD_META_PROP, ts_field, getattr(mdest, ts_field), getattr(msrc, ts_field)))
                setattr(mdest, ts_field, getattr(msrc, ts_field))
                setattr(mdest, ts_field+'Changed', getattr(msrc, ts_field+'Changed'))
                if self.debug:
                    self._debug("DB Meta Field <{}>: '{}' <-- '{}'".format(ts_field, getattr(mdest, ts_field), getattr(msrc, ts_field)))
        
        # Don't know how to merge binary or customdata...
        assert not mdest.Binaries, mdest.Binaries
        assert not mdest.CustomData, mdest.CustomData

    def _merge_roots(self):
        "Merge Root elements"
        raise UnimplementedError("Must use subclass")

    def _merge_group_metadata(self, gdest, gsrc):
        "Merge metadata from source into dest group"
        #~ <Name>NSA Backdoors</Name>
        #~ <Notes />
        #~ <IconID>1</IconID>
        #~ <Times>
                #~ <CreationTime>2016-06-04T09:45:41Z</CreationTime>
                #~ <LastModificationTime>2016-06-04T09:45:41Z</LastModificationTime>
                #~ <LastAccessTime>2016-06-04T09:48:32Z</LastAccessTime>
                #~ <ExpiryTime>2016-06-04T09:45:41Z</ExpiryTime>
                #~ <Expires>False</Expires>
                #~ <UsageCount>2</UsageCount>
                #~ <LocationChanged>2016-06-04T09:45:41Z</LocationChanged>
        #~ </Times>
        #~ <IsExpanded>True</IsExpanded>
        #~ <DefaultAutoTypeSequence />
        #~ <EnableAutoType>null</EnableAutoType>
        #~ <EnableSearching>null</EnableSearching>
        #~ <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
        do_merge = True
        if gdest.find('./Times/LastModificationTime'):
            do_merge = parse_timestamp(gdest.Times.LastModificationTime) < \
                       parse_timestamp(gsrc.Times.LastModificationTime)
            
            # Still should copy Times if modification dates are the same
            # because last access time and usage count could be different.
            if (parse_timestamp(gdest.Times.LastModificationTime) == \
                parse_timestamp(gsrc.Times.LastModificationTime)) and \
               (parse_timestamp(gdest.Times.LastAccessTime) < \
                parse_timestamp(gsrc.Times.LastAccessTime)):
                gdest.Times = deepcopy(gsrc.Times)
        
        if do_merge:
            isnew = (len(gdest.getchildren())==0)
            changes = []
            new_elems = []
            for gesrc in gsrc.getchildren():
                # everything but Group and Entry elements are metadata
                if gesrc.tag in ('Group', 'Entry'):
                    continue
                
                gedest = getattr(gdest, gesrc.tag, None)
                if gedest is None:
                    # If element doesn't exist in dest, append a copy
                    new_elems.append(deepcopy(gesrc))
                    changes.append((gesrc.tag, None, lxml.etree.tostring(gesrc)))
                    mm_op = (KDBMergeOps.MOPS_ADD_PROP, gdest, new_elems[-1])
                elif len(gesrc.getchildren()) > 0 or len(gedest.getchildren()) > 0:
                    # If either subelements have subelements themselves...
                    mm_op = (KDBMergeOps.MOPS_MOD_PROP, gdest, deepcopy(gedest), deepcopy(gesrc))
                    changes.append((gesrc.tag, lxml.etree.tostring(gedest), lxml.etree.tostring(gesrc)))
                    gdest.replace(gedest, deepcopy(gesrc))
                elif gedest.text != gesrc.text:
                    # Treat as subelements with text nodes
                    mm_op = (KDBMergeOps.MOPS_MOD_PROP, gdest, deepcopy(gedest), deepcopy(gesrc))
                    changes.append((gesrc.tag, gedest.text, gesrc.text))
                    gedest.text = gesrc.text
                
                if not isnew:
                    self.mm_ops.append(mm_op)
            else:
                # Add new subelements before any Entry or Group subelements
                prepend_elem = getattr(gdest, 'Entry', None) or getattr(gdest, 'Group', None)
                if prepend_elem:
                    for elem in new_elems:
                        prepend_elem.addprevious(elem)
                else:
                    gdest.extend(new_elems)
            
            if self.debug and changes:
                self._debug("Differing Group [%s]%s"%(gdest.UUID.text, get_pw_path(gdest)))
                for tag, cdest, csrc in changes:
                    if cdest != csrc:
                        self._debug("%s: %r <-- %r"%(tag, cdest, csrc))
            
            return True
        return False

    def _merge_entry(self, edest, esrc):
        """Merge entries only if the src has a newer last modification time than
           the dest.  Dest relocation will occur if location changed date for
           src is newer and the containing groups are different.
        """
        #~ <IconID>1</IconID>
        #~ <ForegroundColor />
        #~ <BackgroundColor />
        #~ <OverrideURL />
        #~ <Tags />
        #~ <Times>
                #~ <CreationTime>2013-07-05T18:21:01Z</CreationTime>
                #~ <LastModificationTime>2013-07-05T18:22:26Z</LastModificationTime>
                #~ <LastAccessTime>2013-07-05T18:22:26Z</LastAccessTime>
                #~ <ExpiryTime>2016-06-04T09:45:41Z</ExpiryTime>
                #~ <Expires>False</Expires>
                #~ <UsageCount>0</UsageCount>
                #~ <LocationChanged>2016-06-04T09:45:41Z</LocationChanged>
        #~ </Times>
        #~ <String>
                #~ <Key>Notes</Key>
                #~ <Value />
        #~ </String>
        #~ <String>
                #~ <Key>Password</Key>
                #~ <Value ProtectInMemory="True">9600Ympk72NbEvTtcrV404Nc</Value>
        #~ </String>
        #~ <String>
                #~ <Key>Title</Key>
                #~ <Value>NSA - root</Value>
        #~ </String>
        #~ <String>
                #~ <Key>URL</Key>
                #~ <Value>nsa.gov</Value>
        #~ </String>
        #~ <String>
                #~ <Key>UserName</Key>
                #~ <Value>r00t</Value>
        #~ </String>
        #~ <AutoType>
                #~ <Enabled>True</Enabled>
                #~ <DataTransferObfuscation>0</DataTransferObfuscation>
        #~ </AutoType>
        #~ <History />
        if self.debug:
            self._debug("merging entry:", get_pw_path(esrc))
        
        eLocationChanged = False
        if edest.find('./Times/LocationChanged'):
            eLocationChanged = parse_timestamp(edest.Times.LocationChanged) < \
                               parse_timestamp(esrc.Times.LocationChanged) and \
                               (edest.getparent().UUID != esrc.getparent().UUID)
        
        cmp_lastmod = self._cmp_lastmod(edest, esrc)
        
        if len(edest.getchildren()) == 0:
            # Newly added entry...
            self.mm_ops.append((KDBMergeOps.MOPS_ADD_ENTRY, edest))
            edest.extend(deepcopy(esrc).getchildren())
        elif self.mode == self.MM_SYNCHRONIZE_3WAY:
            # Only do this if edest is not a new element
            eanctr = self._find_common_ancestor(edest, esrc)
            cmp_lastmod_eanctr_edest = self._cmp_lastmod(eanctr, edest)
            cmp_lastmod_eanctr_esrc = self._cmp_lastmod(eanctr, esrc)
            assert cmp_lastmod_eanctr_edest <= 0
            assert cmp_lastmod_eanctr_esrc <= 0
            
            if cmp_lastmod_eanctr_edest < 0 and cmp_lastmod_eanctr_esrc < 0:
                if self.debug:
                    self._debug("UUID %s has both dest and src that have been modified."%edest.UUID.text)
                # === 3-way merge of entries ===
                self._merge_entry_item_3way(edest, esrc, eanctr, touch=True)
            elif cmp_lastmod_eanctr_edest < 0:
                assert cmp_lastmod_eanctr_esrc == 0
                if self.debug:
                    self._debug("  Source is ancestor of dest, do nothing")
                # source is an ancestor of dest, so we don't need to do anything
            elif cmp_lastmod_eanctr_esrc < 0:
                assert cmp_lastmod_eanctr_edest == 0
                assert edest == eanctr, (edest, eanctr)
                if self.debug:
                    self._debug("  Dest is an ancestor of source, replace with source")
                # dest is an ancestor of source, so replace dest with source
                self._merge_entry_item_3way(edest, esrc, eanctr, touch=False)
            else:
                # dest, src, and ancestor all have same age
                assert cmp_lastmod == 0
                if self.debug:
                    self._debug("  Should be same unmodified entry, except for access time")
                # Still should copy Times if access date is newer because
                # last access time and usage count could be different.
                if parse_timestamp(edest.Times.LastAccessTime) < \
                   parse_timestamp(esrc.Times.LastAccessTime):
                    self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(edest.Times.LastAccessTime), deepcopy(esrc.Times.LastAccessTime)))
                    edest.Times.LastAccessTime._setText(esrc.Times.LastAccessTime.text)
                    if int(edest.Times.UsageCount.text) != int(esrc.Times.UsageCount.text):
                        self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(edest.Times.UsageCount), deepcopy(esrc.Times.UsageCount)))
                        edest.Times.UsageCount._setText(esrc.Times.UsageCount.text)
            
        elif cmp_lastmod < 0:
            # Not a 3way merge, a regular entry level merge where dest is older
            # than source.
            # Make copy of edest to put in the History element later on
            edest_orig = deepcopy(edest)
            edest_orig_hist = edest_orig.find('./History')
            if edest_orig_hist is not None:
                edest_orig.remove(edest_orig_hist)
            
            if getattr(edest, 'History', None) is None:
                edest.append(edest.makeelement('History'))
            # Add original entry to History
            edest.History.append(edest_orig)
            if len(edest.History.getchildren()) > 1:
                assert edest_orig.Times.LastModificationTime > edest.History.getchildren()[-2].Times.LastModificationTime
            
            changes = []
            new_elems = []
            for eesrc in esrc.getchildren():
                if eesrc.tag == 'String':
                    # Need to find String element with matching Key text
                    kvs = edest.findall("./String[Key='%s']"%eesrc.Key.text)
                    assert len(kvs) <= 1, (edest.UUID.text, eesrc.Key.text, kvs)
                    if len(kvs) == 0:
                        # not in dest, so add it
                        self.mm_ops.append((KDBMergeOps.MOPS_ADD_PROP, edest, deepcopy(eesrc)))
                        changes.append(('+s'+eesrc.Key.text, None, eesrc.Value.text))
                        # Add before the History element if it exists or append to end
                        edest_last_chld = (edest.getchildren() + [None])[-1]
                        if edest_last_chld is None:
                            edest.append(deepcopy(eesrc))
                        elif edest_last_chld.tag == 'History':
                            edest_last_chld.addprevious(deepcopy(eesrc))
                        else:
                            edest_last_chld.addnext(deepcopy(eesrc))
                        
                    elif len(kvs) == 1 and (kvs[0].Value.text != eesrc.Value.text):
                        # dest has a string with this key and the values are different
                        self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(kvs[0]), deepcopy(eesrc)))
                        changes.append(('~s'+eesrc.Key.text, kvs[0].Value.text, eesrc.Value.text))
                        kvs[0].replace(kvs[0].Value, deepcopy(eesrc.Value))
                    
                elif eesrc.tag == 'History':
                    pass
                else:
                    mchanges, mnew_elems = self._merge_metadata_item_common(edest, eesrc)
                    changes += mchanges
                    new_elems += mnew_elems
            else:
                # Add new subelements to the end
                edest.extend(new_elems)
            
            if self.debug and changes:
                self._debug("Differing Entry [%s]%s"%(edest.UUID.text, get_pw_path(edest)))
                for tag, cdest, csrc in changes:
                    self._debug("  %s: %r <-- %r"%(tag, cdest, csrc))
        elif cmp_lastmod > 0:
            # Since dest is newer than source, only need to add source to
            # dest's history, if not already there.
            
            # Make copy of esrc to put in the History element later on
            esrc_copy = deepcopy(esrc)
            esrc_copy_hist = esrc_copy.find('./History')
            if esrc_copy_hist is not None:
                esrc_copy.remove(esrc_copy_hist)
            
            if getattr(edest, 'History', None) is None:
                edest.append(edest.makeelement('History'))
            
            # If src is not in dest's history, add it in chronologically
            for ehdest in edest.History.getchildren()[::-1]:
                _cmp = self._cmp_lastmod(ehdest, esrc)
                if _cmp == 0:
                    break
                elif _cmp < 0:
                    ehdest.addnext(esrc_copy)
                    break
                elif _cmp > 0:
                    continue
            else:
                assert 0, "Either dest has no history or src is older than the oldest history item..."
        
        elif cmp_lastmod == 0:
            # Same last modification time but might have different access times
            # and usage counts.
            if parse_timestamp(edest.Times.LastAccessTime) < \
               parse_timestamp(esrc.Times.LastAccessTime):
                self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(edest.Times.LastAccessTime), deepcopy(esrc.Times.LastAccessTime)))
                edest.Times.LastAccessTime._setText(esrc.Times.LastAccessTime.text)
                if int(edest.Times.UsageCount.text) != int(esrc.Times.UsageCount.text):
                    self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(edest.Times.UsageCount), deepcopy(esrc.Times.UsageCount)))
                    edest.Times.UsageCount._setText(esrc.Times.UsageCount.text)
        
        # Always merge history
        self._merge_history(edest, esrc.History)
        
        if eLocationChanged and (self.mode in (self.MM_SYNCHRONIZE, self.MM_SYNCHRONIZE_3WAY)):
            self._merge_location_change(edest, esrc)

    def _merge_entry_item_3way(self, edest, esrc, eanctr, touch=True):
        "Merge two entries using a common ancestor entry"
        cmp_lastmod = self._cmp_lastmod(edest, esrc)
        # It would be absurd if both entries were modified independently at the
        # same second!
        assert cmp_lastmod != 0, (edest, esrc)
        
        # Make copy of edest to put in the History element later on
        edest_orig = deepcopy(edest)
        edest_orig_hist = edest_orig.find('./History')
        if edest_orig_hist is not None:
            edest_orig.remove(edest_orig_hist)
        
        esrc_orig = deepcopy(esrc)
        esrc_orig_hist = esrc_orig.find('./History')
        if esrc_orig_hist is not None:
            esrc_orig.remove(esrc_orig_hist)
        
        if getattr(edest, 'History', None) is None:
            edest.append(edest.makeelement('History'))
        
        # start doing the merge
        changes = []
        new_elems = []
        lsanctr_deletions = eanctr.findall('./String')
        for eesrc in esrc.getchildren():
            if eesrc.tag == 'String':
                # Need to find String element with matching Key text
                lsanctr = eanctr.findall("./String[Key='%s']"%eesrc.Key.text)
                assert len(lsanctr) <= 1, (edest.UUID.text, eesrc.Key.text, kvs)
                if len(lsanctr) == 1:
                    lsanctr_deletions.remove(lsanctr[0])
                # Did source make a change to this string?
                if len(lsanctr) == 1 and eesrc.Value.text == lsanctr[0].Value.text:
                    # source made no change, so keep dest version
                    continue
                
                lsdest = edest.findall("./String[Key='%s']"%eesrc.Key.text)
                assert len(lsdest) <= 1, (edest.UUID.text, eesrc.Key.text, lsdest)
                
                # Did dest make a change?
                if len(lsdest) == 1 and lsdest[0].Value.text == eesrc.Value.text:
                    # If source and dest are the same, do nothing
                    continue
                elif len(lsanctr) == 1 and len(lsdest) == 1 and lsdest[0].Value.text == lsanctr[0].Value.text:
                    # dest did not change from ancestor, so use source version
                    self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(lsdest[0]), deepcopy(eesrc)))
                    changes.append(('~s'+eesrc.Key.text, lsdest[0].Value.text, eesrc.Value.text))
                    lsdest[0].replace(lsdest[0].Value, deepcopy(eesrc.Value))
                    continue
                
                # both source and dest values changed
                if cmp_lastmod < 0:
                    # source was modified last
                    if len(lsdest) == 0:
                        # dest does not have this key, so add it
                        eesrc_copy = deepcopy(eesrc)
                        changes.append(('+s'+eesrc.Key.text, None, eesrc.Value.text))
                        self.mm_ops.append((KDBMergeOps.MOPS_ADD_PROP, edest, eesrc_copy))
                        # Try to add after last String, then after Times,
                        # then before History, else at the end.
                        try:
                            edest.String[-1].addnext(eesrc_copy)
                        except AttributeError:
                            try:
                                edest.Times.addnext(eesrc_copy)
                            except AttributeError:
                                try:
                                    edest.History.addprevious(eesrc_copy)
                                except AttributeError:
                                    edest.append(eesrc_copy)
                    else:
                        # dest does have key, so update value
                        self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, edest, deepcopy(lsdest[0]), deepcopy(eesrc)))
                        changes.append(('~s'+eesrc.Key.text, lsdest[0].Value.text, eesrc.Value.text))
                        lsdest[0].Value._setText(eesrc.Value.text)
                #~ else: # dest was modified last, do nothing
            elif eesrc.tag == 'History':
                # Already dealt with History
                pass
            else:
                # Merge in the non special cases
                mchanges, mnew_elems = self._merge_metadata_item_3way_common(edest, eesrc, eanctr, cmp_lastmod)
                changes += mchanges
                new_elems += mnew_elems
        else:
            # Add new subelements to the end
            edest.extend(new_elems)
        
        if changes:
            if touch:
                # There were changes and we want to update the timestamps
                self._touch(edest, True)
            
            if self.debug:
                self._debug("Differing Entry [%s]%s"%(edest.UUID.text, get_pw_path(edest)))
                for tag, cdest, csrc in changes:
                    self._debug("  %s: %r <-- %r"%(tag, cdest, csrc))
        
        if edest == eanctr:
            # edest is ancestor of source, which means that edest should be
            # changed into source now. And edest is in the source history,
            # which will get merged later. So do nothing.
            pass
        # Add source and dest to dest history if needed
        elif cmp_lastmod < 0:
            # If dest is older than src
            edest.History.extend([edest_orig, esrc_orig])
        elif cmp_lastmod > 0:
            # If src is older than dest, put it in the right place in the
            # history list.
            for ehdest in edest.History.getchildren()[::-1]:
                if self._cmp_lastmod(ehdest, esrc_orig) < 0:
                    ehdest.addnext(esrc_orig)
                    break
            edest.History.extend([edest_orig])
        # Sanity checks...
        if len(edest.History.getchildren()) > 2:
            assert edest_orig.Times.LastModificationTime > edest.History.getchildren()[-3].Times.LastModificationTime
            assert esrc_orig.Times.LastModificationTime > edest.History.getchildren()[-3].Times.LastModificationTime
        
        # Handle String deletions
        for anctr_del in lsanctr_deletions:
            if cmp_lastmod < 0:
                # source is newer, but didn't have this string, so source
                # must have deleted it, so delete in dest
                lsdest = edest.findall("./String[Key='%s']"%anctr_del.Key.text)
                assert len(lsdest) <= 1, (edest.UUID.text, anctr_del.Key.text, lsdest)
                if len(lsdest) == 1:
                    self.mm_ops.append((KDBMergeOps.MOPS_DEL_PROP, edest, deepcopy(lsdest[0])))
                    edest.remove(lsdest[0])
                    if self.debug:
                        self._debug("[%s] Removing String key %s"%(edest.UUID.text, anctr_del.Key.text))
        

    def _merge_metadata_item_3way_common(self, pdest, src, panctr, cmp_lastmod):
        "Merge metadata items that do not need special attention"
        # Assume that no elements have both subelements and inner text
        # Also assume that there can not be deletions of items...
        changes = []
        new_elems = []
        dest = getattr(pdest, src.tag, None)
        anctr = getattr(panctr, src.tag, None)
        src_copy = deepcopy(src)
        
        # common predicates
        has_dest = (dest is not None)
        has_anctr = (anctr is not None)
        src_newer = (cmp_lastmod < 0)
        
        # Assert this for now because the only elements of and entry that can
        # be deleted or added are extra Strings
        # Maybe not true, if later version of KeePass removes depreciated
        # elements.
        assert has_anctr
        
        if has_dest and elem_tree_equal(src, dest):
            # source and dest are the same, so do nothing
            pass
        elif elem_tree_equal(src, anctr):
            # source not modified, use dest unchanged
            if not has_dest:
                # unless there is no dest, in which case use source
                self.mm_ops.append((KDBMergeOps.MOPS_ADD_PROP, pdest, src_copy))
                new_elems.append(src_copy)
                changes.append(('~+'+src.tag, '', lxml.etree.tostring(src)))
        elif cmp_lastmod < 0:
            # source was modified, and source newer than dest
            if not has_dest:
                # No dest, so just append to dest parent
                self.mm_ops.append((KDBMergeOps.MOPS_ADD_PROP, pdest, src_copy))
                new_elems.append(src_copy)
                changes.append(('~+'+src.tag, '', lxml.etree.tostring(src)))
            else:
                # have dest, but its older, so use source
                self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, pdest, deepcopy(dest), src_copy))
                pdest.replace(dest, src_copy)
                if elem_tree_equal(dest, anctr):
                    # dest was modified too
                    changes.append(('~-'+src.tag, '', lxml.etree.tostring(dest)))
                changes.append(('~+'+src.tag, '', lxml.etree.tostring(src)))
        #~ else: # source modified, but older or same age as dest
        
        return (changes, new_elems)
    
    def _merge_metadata_item_common(self, pdest, src, anctr=None):
        "Merge metadata items that do not need special attention"
        # Assume that no elements have both subelements and inner text
        changes = []
        new_elems = []
        dest = getattr(pdest, src.tag, None)
        
        xmldest = lxml.etree.tostring(dest) if (dest is not None) else None
        xmlsrc = lxml.etree.tostring(src)
        
        if dest is None:
            # If element doesn't exist, append a copy
            new_elems.append(deepcopy(src))
            changes.append(('+'+src.tag, '', xmlsrc))
            self.mm_ops.append((KDBMergeOps.MOPS_ADD_PROP, pdest, new_elems[-1]))
        elif xmldest == xmlsrc:
            # Nothing changed, so do nothing...
            pass
        elif len(src.getchildren()) > 0 or len(dest.getchildren()) > 0:
            # If either subelements have subelements themselves...
            self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, pdest, deepcopy(dest), deepcopy(src)))
            changes.append(('~'+src.tag, xmldest, xmlsrc))
            pdest.replace(dest, deepcopy(src))
        elif dest.text != src.text:
            # Treat as subelements with text nodes
            self.mm_ops.append((KDBMergeOps.MOPS_MOD_PROP, pdest, deepcopy(dest), deepcopy(src)))
            changes.append(('~'+src.tag, dest.text, src.text))
            dest._setText(src.text)
        return (changes, new_elems)
    
    def _merge_history(self, dest, src_hist):
        "Merge src history element into dest"
        if src_hist is None or len(src_hist.getchildren()) == 0:
            # Nothing to merge
            return
        
        dest_hist = dest.find('./History')
        if dest_hist is None:
            dest_hist = dest.makeelement('History')
            dest.append(dest_hist)
        
        pdhist = (dest_hist.getchildren() or [None])[0]
        pshist = (src_hist.getchildren() or [None])[0]
        while (pdhist is not None) or (pshist is not None):
            if pdhist is None:
                # Already reached the end of dest hist list...
                self.mm_ops.append((KDBMergeOps.MOPS_ADD_HISTORY, dest, pshist))
                if self.debug:
                    self._debug("Adding history to '%s' from time %s"% \
                               (dest.UUID.text, pshist.Times.LastModificationTime))
                dest_hist.append(deepcopy(pshist))
                pshist = pshist.getnext()
            elif pshist is None:
                # Reached the end of src hist list, so done
                break
            else:
                _cmp = self._cmp_lastmod(pdhist, pshist)
                if _cmp < 0:
                    pdhist = pdhist.getnext()
                elif _cmp > 0:
                    # Source history item is older, so add it
                    self.mm_ops.append((KDBMergeOps.MOPS_ADD_HISTORY, dest, pshist))
                    if self.debug:
                        self._debug("Adding history to '%s' from time %s"% \
                                   (dest.UUID.text, pshist.Times.LastModificationTime))
                    pdhist.addprevious(deepcopy(pshist))
                    pshist = pshist.getnext()
                else:
                    # Same time stamp, assume same history record
                    pdhist = pdhist.getnext()
                    pshist = pshist.getnext()
    
    def _merge_deleted_objects(self, rdest, rsrc):
        "Merge src deleted objects element into dest"
        dodest = rdest.find("./DeletedObjects")
        dosrc = rsrc.find("./DeletedObjects")
        
        if dosrc is None:
            # No DeletedObjects element in source, so do nothing because we
            # assume that objects referenced in DeletedObjects have already
            # been deleted in the kdb they originate from
            return
        
        if dodest is None:
            dodest = rdest.makeelement('DeletedObjects')
            rdest.append(dodest)
        
        dodest_uuids = {}
        dosrc_uuids = {}
        
        for do in dodest.getchildren():
            dodest_uuids[do.UUID.text] = do
        
        for do in dosrc.getchildren():
            if do.UUID.text in dodest_uuids:
                # Source deleted object exists in dest, so skip it
                if parse_timestamp(dodest_uuids[do.UUID.text].DeletionTime) < \
                   parse_timestamp(do.DeletionTime):
                    # Keep the most recent deletion time...
                    dodest_uuids[do.UUID.text].DeletionTime = do.DeletionTime
                continue
            
            # For each deleted objects in source that is not in dest, add
            # to dest.
            dodest.append(deepcopy(do))
            if self.debug:
                self._debug("Adding deleted object '%s' at time %s"% \
                           (do.UUID.text, do.DeletionTime.text))
            
            # Check if the tree has any elements with UUIDs matching a deleted
            # UUID.
            del_uuids = [u for u in rdest.findall(".//*[UUID='%s']"%do.UUID.text)
                           if u.getparent().tag != 'History']
            assert len(del_uuids) in (1, 2), del_uuids
            
            if len(del_uuids) > 1:
                del_el = del_uuids[0]
                if del_uuids[0].tag == 'DeletedObject':
                    del_el = del_uuids[1]
                if parse_timestamp(del_el.Times.LastModificationTime) < \
                   parse_timestamp(do.DeletionTime):
                    # If the deletion time is newer than the lastmod,
                    # the element has been deleted since its lastmod, so
                    # delete. Otherwise the element was deleted in one
                    # kdb and modified after the deletion time in another
                    # kdb, thus we should keep it.
                    if del_el.tag == 'Group':
                        mop = KDBMergeOps.MOPS_DEL_GROUP
                    elif del_el.tag == 'Entry':
                        mop = KDBMergeOps.MOPS_DEL_ENTRY
                    else:
                        raise Exception("Unsupported deleted element: %s"%del_el.tag)
                    self.mm_ops.append((mop, del_el, get_pw_path(del_el), do.DeletionTime.text))
                    del_el.getparent().remove(del_el)
                    if self.debug:
                        self._debug("Deleting deleted object '%s' at time %s"% \
                                   (del_el.UUID.text, do.DeletionTime.text))

    def _find_common_ancestor(self, edest, esrc):
        "Find most recent common historical ancestor to two entries."
        # Common ancestors are defined solely by having history items with
        # matching timestamps.  Entries with matching timestamps are assumed
        # to be identical.
        # Must only be used on the same element
        assert edest.UUID.text == esrc.UUID.text, (edest.UUID.text, esrc.UUID.text)
        cmp_lastmod = self._cmp_lastmod(edest, esrc)
        if cmp_lastmod == 0:
            # No modifications, they should be the same
            return edest
        
        edesthist = getattr(edest, 'History', None)
        if edesthist is None:
            edesthist = [edest]
        else:
            edesthist = (edesthist.getchildren()) + [edest]
        
        esrchist = getattr(esrc, 'History', None)
        if edesthist is None:
            esrchist = [esrc]
        else:
            esrchist = (esrchist.getchildren()) + [esrc]
        
        curdesthist = edesthist[0]
        cursrchist  = esrchist[0]
        # The earliest item in the history should be the same, ie the original
        # entry.  However if it was converted from KBD3 format, this may not be
        # true.  But that breaks all assumptions, so fail for now.
        assert self._cmp_lastmod(curdesthist, cursrchist) == 0, (curdesthist, cursrchist)
        
        
        while edesthist and esrchist:
            cmp_lastmod = self._cmp_lastmod(edesthist[0], esrchist[0])
            if cmp_lastmod == 0:
                curdesthist = edesthist.pop(0)
                cursrchist = esrchist.pop(0)
            else:
                break
        return curdesthist

    def _touch(self, el, lastmod=True):
        "Set timestamp to now"
        modtime_str = unparse_timestamp(datetime.utcnow())
        if lastmod:
            el.Times.LastModificationTime._setText(modtime_str)
        el.Times.LastAccessTime._setText(modtime_str)
        el.Times.UsageCount._setText(str(int(el.Times.UsageCount)+1))

    def _cmp_lastmod(self, el1, el2, tag='LastModificationTime'):
        "Compare el1 and el2 by the last modification time"
        el1_has_times = el1.find('./Times') is not None
        el2_has_times = el2.find('./Times') is not None
        assert el1_has_times or el2_has_times, (el1, el2)
        if not el1_has_times:
            return -2
        if not el2_has_times:
            return 2
        
        el1_modtime = parse_timestamp(getattr(el1.Times, tag))
        el2_modtime = parse_timestamp(getattr(el2.Times, tag))
        return (el1_modtime < el2_modtime and -1) or \
               (el1_modtime > el2_modtime and 1) or 0


class KDB4UUIDMerge(KDB4Merge):
    
    def _new_element(self, pdest, src):
        "Make new element of type src as child of pdest and copy UUIDs"
        assert pdest is not None, pdest
        dest = pdest.makeelement(src.tag)
        # Add element as next sibling of last of same type of element
        # otherwise if its an Entry add before the first Group and if
        # no groups then add as last element
        el = pdest.getchildren()[-1]
        psrc_tags = pdest.findall('./'+src.tag)
        if psrc_tags:
            el = psrc_tags[-1]
        else:
            if src.tag == 'Entry':
                pgrps = pdest.findall('./Group')
                if pgrps:
                    el = pgrps[0].getprevious()
        el.addnext(dest)
        
        self.__dest_uuid_map[src.UUID.text] = dest
        
        return dest
    
    def _merge_roots(self, rdest, rsrc):
        "Merge two Root elements"
        self.__dest_uuid_map = {}
        for uuid in rdest.findall(".//*/UUID"):
            if uuid.getparent().tag not in ('Group', 'Entry'):
                continue
            if uuid.getparent().getparent().tag == 'History':
                continue
            assert uuid.text not in self.__dest_uuid_map, uuid.text
            self.__dest_uuid_map[uuid.text] = uuid.getparent()
        
        self.__dest_uuids_remaining_map = self.__dest_uuid_map.copy()
        
        for gsrc in rsrc.getchildren():
            if gsrc.tag != 'Group':
                assert gsrc.tag != 'Entry', (gsrc.tag, group)
                continue
            gdest = self.__dest_uuid_map.get(gsrc.UUID.text, None)
            r = self.__dest_uuids_remaining_map.pop(gsrc.UUID.text, None)
            assert r is not None or gsrc.UUID.text not in self.__dest_uuid_map, gsrc.UUID.text
            if gdest is None:
                # No source group in dest, so add it
                gdest = self._new_element(rdest, gsrc)
            
            assert gdest.tag == gsrc.tag, (gdest.tag, gdest.UUID.text)
            self._merge_group(gdest, gsrc)
        else:
            # Anything left in self.__dest_uuid_map is a group or entry not in
            # the merge source, and should be left alone
            # But we do want to log for the diff
            if self.debug and self.__dest_uuids_remaining_map:
                self._debug("Items in dest but not in src")
                for uuid, el in self.__dest_uuids_remaining_map.items():
                    self._debug(" *<{}>[{}]".format(el.tag,uuid), get_pw_path(el))
        
        if self.mode in (self.MM_SYNCHRONIZE, self.MM_SYNCHRONIZE_3WAY):
            self._merge_deleted_objects(rdest, rsrc)
        
        del self.__dest_uuid_map

    def _merge_group(self, gdest, gsrc):
        if self.debug:
            self._debug("merging group:", get_pw_path(gsrc))
        
        if len(gdest.getchildren()) == 0:
            self.mm_ops.append((KDBMergeOps.MOPS_ADD_GROUP, gdest))
        
        gLocationChanged = False
        if gdest.find('./Times/LocationChanged'):
            gLocationChanged = parse_timestamp(gdest.Times.LocationChanged) < \
                               parse_timestamp(gsrc.Times.LocationChanged) and \
                               (gdest.getparent().UUID != gsrc.getparent().UUID)
        self._merge_group_metadata(gdest, gsrc)
        
        # merge recursively each group/entry
        for src in gsrc.getchildren():
            if src.tag not in ('Group', 'Entry'):
                continue
            
            added_elem = False
            dest = self.__dest_uuid_map.get(src.UUID.text, None)
            self.__dest_uuids_remaining_map.pop(src.UUID.text, None)
            if dest is None:
                # No source group/entry in dest, so add it
                pdest = self.__dest_uuid_map.get(gsrc.UUID.text, None)
                assert pdest is not None, pdest
                dest = self._new_element(pdest, src)
                added_elem = True
                if self.debug:
                    self._debug("  adding %s[UUID=%s] %s/%s"%(dest.tag, src.UUID.text, get_pw_path(pdest), pw_name(src)))
            
            old_debug = self.debug
            if added_elem and self.debug:
                self.debug = False
            
            assert dest.tag == src.tag, (dest.tag, dest.UUID.text)
            if src.tag == 'Group':
                self._merge_group(dest, src)
            elif src.tag == 'Entry':
                self._merge_entry(dest, src)
            
            self.debug = old_debug
        
        if gLocationChanged and (self.mode in (self.MM_SYNCHRONIZE, self.MM_SYNCHRONIZE_3WAY)):
            self._merge_location_change(gdest, gsrc)
    
    def _merge_location_change(self, dest, src):
        "Relocate dest group/entry to same path as source group"
        assert dest.tag == src.tag
        assert dest.tag in ('Group', 'Entry'), dest.tag
        
        pdest = dest.getparent()
        psrc = src.getparent()
        assert pdest.UUID.text != psrc.UUID.text, (pdest.UUID.text, psrc.UUID.text)

        old_path = get_pw_path(dest)
        pdest.remove(dest)
        pdest = self.__dest_uuid_map[psrc.UUID.text]
        pdest.append(dest)
        self.mm_ops.append((KDBMergeOps.MOPS_MOVE, dest, old_path))
        if self.debug:
            self._debug(" * Move %s %s to %s"%(dest.tag, old_path, get_pw_path(dest)))
        
        # Update location changed time
        dest.Times.LocationChanged = src.Times.LocationChanged


class KDB4PathMerge(KDB4Merge):
    pass


def merge_kdb4(kdb_a, kdb_b, *args, **kwargs):
    "Merge two KDB4 databases"
    return KDB4Merge(kdb_a, ).merge()


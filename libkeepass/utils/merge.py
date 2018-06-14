# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import os
import datetime
from datetime import datetime
from copy import deepcopy

import lxml.etree
import lxml.objectify


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
            val = sys.stderr
        self.__debug = val

    @staticmethod
    def _parse_ts(date_text):
        return datetime.strptime(str(date_text), '%Y-%m-%dT%H:%M:%SZ')


class KDB4Merge(KDBMerge):
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

    def __init__(self, kdb_dest, kdb_src, metadata=False, debug=False):
        self.kdb_dest, self.kdb_src = kdb_dest, kdb_src
        self.metadata = metadata
        self.debug = debug
        
        assert self.__class__ != KDB4Merge, "Must use subclass of KDB4Merge"
        
        # All newer entries from kdb_src should overwrite entries in kdb_dest.
        assert hasattr(kdb_dest, 'obj_root'), kdb_dest
        assert hasattr(kdb_src,  'obj_root'), kdb_src
        
        self.mm_ops = []

    def print_mm_ops(self, file=sys.stdout):
        if not self.mm_ops:
            print("Merge made no changes")
            return
        
        prev_el = None
        print("Merge changes:", file=file)
        for op in self.mm_ops:
            opcode, vals = op[0], op[1:]
            
            if prev_el is None or prev_el != vals[0]:
                # If the header for this element hasn't been printed yet,
                # then print it for certain merge ops.
                if opcode in (self.MOPS_ADD_PROP, self.MOPS_MOD_PROP, self.MOPS_DEL_PROP, self.MOPS_MOD_META_PROP):
                    print(" ~[{}:{}]{}".format(vals[0].tag, vals[0].UUID.text, get_pw_path(vals[0])), file=file)
        
            if opcode == self.MOPS_MOVE:
                print(" >[{}:{}]{}".format(vals[0].tag, vals[0].UUID.text, vals[1]), file=file)
                print("        ->", get_pw_path(vals[0]), file=file)
            elif opcode == self.MOPS_ADD_GROUP:
                print(" +[Group:{}]{}".format(vals[0].UUID.text, get_pw_path(vals[0])), file=file)
            elif opcode == self.MOPS_ADD_ENTRY:
                print(" +[Entry:{}]{}".format(vals[0].UUID.text, get_pw_path(vals[0])), file=file)
            elif opcode == self.MOPS_ADD_PROP:
                if vals[1].tag == 'String':
                    print("    +{} = {}".format('K:'+vals[1].Key.text, vals[1].Value.text), file=file)
                else:
                    print("    +{} = {}".format(vals[1].tag, lxml.etree.tostring(vals[1])), file=file)
            elif opcode == self.MOPS_MOD_PROP:
                oldprop, newprop = vals[1:]
                if oldprop.tag == 'String':
                    print("    ~{}: {} -> {}".format(oldprop.Key.text, oldprop.Value.text, newprop.Value.text), file=file)
                else:
                    print("    ~{}: {} -> {}".format(oldprop.tag, oldprop.text, newprop.text), file=file)
            elif opcode == self.MOPS_MOD_META_PROP:
                print("    ~{}: {} -> {}".format(*vals[1:]), file=file)
            elif opcode == self.MOPS_DEL_GROUP:
                print(" -[Group:{}]{}  <{}>".format(vals[0].UUID.text, vals[1], vals[2]), file=file)
            elif opcode == self.MOPS_DEL_ENTRY:
                print(" -[Entry:{}]{}  <{}>".format(vals[0].UUID.text, vals[1], vals[2]), file=file)
            elif opcode == self.MOPS_DEL_PROP:
                if vals[1].tag == 'String':
                    print("    -{} ".format(vals[1].Key.text), file=file)
                else:
                    print("    -{} ".format(vals[1].tag), file=file)
            elif opcode == self.MOPS_ADD_HISTORY:
                print(" +[{}]{} Add history {}".format(vals[0].UUID.text, get_pw_path(vals[0]), vals[1].Times.LastModificationTime), file=file)
                
            else:
                raise Exception("Unknown merge opcode %r"%opcode)
            prev_el = vals[0]

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
            if self._parse_ts(getattr(mdest, ts_field+'Changed', datetime.utcfromtimestamp(0))) \
             < self._parse_ts(getattr(msrc, ts_field+'Changed')):
                self.mm_ops.append((self.MOPS_MOD_META_PROP, ts_field, getattr(mdest, ts_field), getattr(msrc, ts_field)))
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
            do_merge = self._parse_ts(gdest.Times.LastModificationTime) < \
                       self._parse_ts(gsrc.Times.LastModificationTime)
            
            # Still should copy Times if modification dates are the same
            # because last access time and usage count could be different.
            if (self._parse_ts(gdest.Times.LastModificationTime) == \
                self._parse_ts(gsrc.Times.LastModificationTime)) and \
               (self._parse_ts(gdest.Times.LastAccessTime) < \
                self._parse_ts(gsrc.Times.LastAccessTime)):
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
                    mm_op = (self.MOPS_ADD_PROP, gdest, new_elems[-1])
                elif len(gesrc.getchildren()) > 0 or len(gedest.getchildren()) > 0:
                    # If either subelements have subelements themselves...
                    mm_op = (self.MOPS_MOD_PROP, gdest, deepcopy(gedest), deepcopy(gesrc))
                    changes.append((gesrc.tag, lxml.etree.tostring(gedest), lxml.etree.tostring(gesrc)))
                    gdest.replace(gedest, deepcopy(gesrc))
                elif gedest.text != gesrc.text:
                    # Treat as subelements with text nodes
                    mm_op = (self.MOPS_MOD_PROP, gdest, deepcopy(gedest), deepcopy(gesrc))
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
            eLocationChanged = self._parse_ts(edest.Times.LocationChanged) < \
                               self._parse_ts(esrc.Times.LocationChanged) and \
                               (edest.getparent().UUID != esrc.getparent().UUID)
        
        cmp_lastmod = self._cmp_lastmod(edest, esrc)
        
        if len(edest.getchildren()) == 0:
            # Newly added entry...
            self.mm_ops.append((self.MOPS_ADD_ENTRY, edest))
            edest.extend(deepcopy(esrc).getchildren())
        elif cmp_lastmod < 0:
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
                        self.mm_ops.append((self.MOPS_ADD_PROP, edest, deepcopy(eesrc)))
                        changes.append(('s'+eesrc.Key.text, None, eesrc.Value.text))
                        # Add before the History element if it exists or append to end
                        edest_last_chld = (edest.getchildren() + [None])[-1]
                        if edest_last_chld is None:
                            edest.append(deepcopy(eesrc))
                        elif edest_last_chld.tag == 'History':
                            edest_last_chld.addprevious(deepcopy(eesrc))
                        else:
                            edest_last_chld.addnext(deepcopy(eesrc))
                        
                    elif len(kvs) == 1:
                        self.mm_ops.append((self.MOPS_MOD_PROP, edest, deepcopy(kvs[0]), deepcopy(eesrc)))
                        changes.append(('s'+eesrc.Key.text, kvs[0].Value.text, eesrc.Value.text))
                        kvs[0].replace(kvs[0].Value, deepcopy(eesrc.Value))
                    
                elif eesrc.tag == 'History':
                    pass
                else:
                    mchanges, mnew_elems = self._merge_metadata_item(edest, eesrc)
                    changes += mchanges
                    new_elems += mnew_elems
            else:
                # Add new subelements to the end
                edest.extend(new_elems)
            
            if self.debug and changes:
                self._debug("Differing Entry [%s]%s"%(edest.UUID.text, get_pw_path(edest)))
                for tag, cdest, csrc in changes:
                    if cdest != csrc:
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
            if self._parse_ts(edest.Times.LastAccessTime) < \
               self._parse_ts(esrc.Times.LastAccessTime):
                self.mm_ops.append((self.MOPS_MOD_PROP, edest, deepcopy(edest.Times.LastAccessTime), deepcopy(esrc.Times.LastAccessTime)))
                edest.Times.LastAccessTime._setText(esrc.Times.LastAccessTime.text)
                if int(edest.Times.UsageCount.text) != int(esrc.Times.UsageCount.text):
                    self.mm_ops.append((self.MOPS_MOD_PROP, edest, deepcopy(edest.Times.UsageCount), deepcopy(esrc.Times.UsageCount)))
                    edest.Times.UsageCount._setText(esrc.Times.UsageCount.text)
        
        # Always merge history
        self._merge_history(edest, esrc.History)
        
        if eLocationChanged:
            self._merge_location_change(edest, esrc)

    def _merge_metadata_item(self, pdest, src):
        "Merge metadata items that do not need special attention"
        # Assume that no elements have both subelements and inner text
        changes = []
        new_elems = []
        dest = getattr(pdest, src.tag, None)
        if dest is None:
            # If element doesn't exist, append a copy
            self.mm_ops.append((self.MOPS_ADD_PROP, pdest, deepcopy(src)))
            new_elems.append(deepcopy(src))
            changes.append((src.tag, '', lxml.etree.tostring(src)))
        elif len(src.getchildren()) > 0 or len(dest.getchildren()) > 0:
            # If either subelements have subelements themselves...
            self.mm_ops.append((self.MOPS_MOD_PROP, pdest, deepcopy(dest), deepcopy(src)))
            changes.append((src.tag, lxml.etree.tostring(dest), lxml.etree.tostring(src)))
            pdest.replace(dest, deepcopy(src))
        elif dest.text != src.text:
            # Treat as subelements with text nodes
            self.mm_ops.append((self.MOPS_MOD_PROP, pdest, deepcopy(dest), deepcopy(src)))
            changes.append((src.tag, dest.text, src.text))
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
                self.mm_ops.append((self.MOPS_ADD_HISTORY, dest, pshist))
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
                    self.mm_ops.append((self.MOPS_ADD_HISTORY, dest, pshist))
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
                if self._parse_ts(dodest_uuids[do.UUID.text].DeletionTime) < \
                   self._parse_ts(do.DeletionTime):
                    # Keep the most recent deletion time...
                    dodest_uuids[do.UUID.text].DeletionTime = do.DeletionTime
                continue
            
            # For each deleted objects in source that is not in dest, add
            # to dest.
            dodest.append(deepcopy(do))
            if self.debug:
                self._debug("Adding deleted object '{}' at time {}"% \
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
                if self._parse_ts(del_el.Times.LastModificationTime) < \
                   self._parse_ts(do.DeletionTime):
                    # If the deletion time is newer than the lastmod,
                    # the element has been deleted since its lastmod, so
                    # delete. Otherwise the element was deleted in one
                    # kdb and modified after the deletion time in another
                    # kdb, thus we should keep it.
                    if del_el.tag == 'Group':
                        mop = MOPS_DEL_GROUP
                    elif del_el.tag == 'Entry':
                        mop = MOPS_DEL_ENTRY
                    else:
                        raise Exception("Unsupported deleted element: %s"%del_el.tag)
                    self.mm_ops.append((mop, del_el, get_pw_path(del_el), do.DeletionTime.text))
                    del_el.getparent().remove(del_el)
                    if self.debug:
                        self._debug("Deleting deleted object '{}' at time {}"% \
                                   (del_el.UUID.text, do.DeletionTime.text))

    def _cmp_lastmod(self, el1, el2):
        "Compare el1 and el2 by the last modification time"
        el1_has_times = el1.find('./Times') is not None
        el2_has_times = el2.find('./Times') is not None
        assert el1_has_times or el2_has_times, (el1, el2)
        if not el1_has_times:
            return -2
        if not el2_has_times:
            return 2
        
        el1_modtime = self._parse_ts(el1.Times.LastModificationTime) 
        el2_modtime = self._parse_ts(el2.Times.LastModificationTime) 
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
        
        self._merge_deleted_objects(rdest, rsrc)
        
        del self.__dest_uuid_map

    def _merge_group(self, gdest, gsrc):
        if self.debug:
            self._debug("merging group:", get_pw_path(gsrc))
        
        if len(gdest.getchildren()) == 0:
            self.mm_ops.append((self.MOPS_ADD_GROUP, gdest))
        
        gLocationChanged = False
        if gdest.find('./Times/LocationChanged'):
            gLocationChanged = self._parse_ts(gdest.Times.LocationChanged) < \
                               self._parse_ts(gsrc.Times.LocationChanged) and \
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
        
        if gLocationChanged:
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
        self.mm_ops.append((self.MOPS_MOVE, dest, old_path))
        if self.debug:
            self._debug(" * Move %s %s to %s"%(dest.tag, old_path, get_pw_path(dest)))
        
        # Update location changed time
        dest.Times.LocationChanged = src.Times.LocationChanged


class KDB4PathMerge(KDB4Merge):
    pass


def merge_kdb4(kdb_a, kdb_b, *args, **kwargs):
    "Merge two KDB4 databases"
    return KDB4Merge(kdb_a, ).merge()


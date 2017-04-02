# -*- coding: utf-8 -*-
import io
import uuid
import zlib
import struct
import hashlib
import base64
import random
import datetime
from binascii import * # for entry id

from libkeepass.crypto import xor, sha256, aes_cbc_decrypt
from libkeepass.crypto import transform_key, unpad

from libkeepass.common import load_keyfile, stream_unpack
from libkeepass.common import KDBFile, HeaderDictionary


KDB3_SIGNATURE = (0x9AA2D903, 0xB54BFB65)


def parse_null_turminated(a_string):
    """
    Strips the first null byte '\x00' from the given argument and returns a
    string/unicode object. Works on strings in python 2 and on byte strings
    in python 3.
    """
    a_string = a_string.replace('\x00'.encode('utf8'), ''.encode('utf8'))
    return a_string.decode('utf8')


class KDB3Header(HeaderDictionary):
    fields = {
        # encryption type/flag
        'Flags': 0,
        'Version': 1,
        # seed to hash the transformed master key
        'MasterSeed': 2,
        'EncryptionIV': 3,
        # fields describing data structure
        'Groups': 4,
        'Entries': 5,
        # hash of the whole decrypted data
        'ContentHash': 6,
        # seed for key transformation
        'MasterSeed2': 7,
        # number of transformation rounds
        'KeyEncRounds': 8,
    }

    fmt = {0: '<I', 4: '<I', 5: '<I', 8: '<I'}

    lengths = [4, 4, 16, 16, 4, 4, 32, 32, 4]

    # TODO how is that field encoded!? it's supposed to be a bitmap, but i get 3.
    encryption_flags = {
        1: 'SHA2',
        #2: 'Rijndael',
        2: 'AES',
        4: 'ArcFour',
        8: 'Twofish',
    }


class KDB3File(KDBFile):
    def __init__(self, stream=None, **credentials):
        self.header = KDB3Header()
        KDBFile.__init__(self, stream, **credentials)

    def _read_header(self, stream):
        """
        Parses the header and write the values into self.header. Also sets
        self.header_length.
        """
        # kdb3 has a fixed header length
        self.header_length = 124
        # skip file signature
        stream.seek(8)

        for field_id, length in enumerate(self.header.lengths):
            data = stream_unpack(stream, None, length, '{}s'.format(length))
            self.header.b[field_id] = data

        # this is impossible, as long as noone messes with self.header.lengths
        if self.header_length != stream.tell():
            raise IOError('Unexpected header length! What did you do!?')

    def _decrypt(self, stream):
        super(KDB3File, self)._decrypt(stream)

        if self.header.encryption_flags[self.header.Flags-1] == 'AES':
            data = aes_cbc_decrypt(stream.read(), self.master_key,
                               self.header.EncryptionIV)
            data = unpad(data)
        elif self.header.encryption_flags[self.header.Flags-1] == 'Twofish':
            data = twofish_cbc_decrypt(stream.read(), self.master_key,
                               self.header.EncryptionIV)
            data = unpad(data)
        else:
            raise IOError('Unsupported encryption type: %s'%self.header.encryption_flags.get(self.header['Flags']-1, self.header['Flags']-1))

        if self.header.ContentHash == sha256(data):
            # put data in bytes io
            self.in_buffer = io.BytesIO(data)
            # set successful decryption flag
            self.opened = True
        else:
            raise IOError('Master key invalid.')

    def _make_master_key(self):
        """
        Make the master key by (1) combining the credentials to create 
        a composite hash, (2) transforming the hash using the transform seed
        for a specific number of rounds and (3) finally hashing the result in 
        combination with the master seed.
        """
        super(KDB3File, self)._make_master_key()
        # print "masterkey:", ''.join(self.keys).encode('hex')
        #composite = sha256(''.join(self.keys))
        #TODO python-keepass does not support keyfiles, there seems to be a
        # different way to hash those keys in kdb3
        composite = self.keys[0]
        tkey = transform_key(composite,
                             self.header.MasterSeed2,
                             self.header.KeyEncRounds)
        self.master_key = sha256(self.header.MasterSeed + tkey)


from xml.sax.saxutils import escape
from lxml import etree

class KDBExtension:
    """
    The KDB3 payload is a binary blob of groups followed by entries.
    """
    # Liberally copied from https://github.com/shirou/kptool/blob/master/kptool/keepassdb/keepassdb.py

    def __init__(self):
        self.in_buffer.seek(0)
        self.entries_by_id = {}
        self.groups_by_id = {}
        self.icons = []
        self.metainfo = []
        self.groups, self.entries = self._parse_body()

    def pretty_print(self):
        """Return a serialization of the element tree."""
        pwentries = []
        for entry in self.entries:
            entry = entry.copy()
            for field in ('title', 'username', 'url', 'password', 'notes'):
                entry[field] = escape(entry[field])
            entry['group'] = escape(entry['group'])
            entry['grp_tree_attr'] = ''
            if 'groups' in self.groups_by_id[entry['group_id']]:
                parent_group_id = self.groups_by_id[entry['group_id']]['groups']
                entry['grp_tree_attr'] = ' tree="{}"'.format(escape(self._get_group_path(parent_group_id)))
            entry['expire_valid'] = (entry['expires'] != datetime.datetime(2999, 12, 28, 23, 59, 59))
            
            pwentries.append(u"""\
<pwentry>
        <group{grp_tree_attr}>{group}</group>
        <title>{title}</title>
        <username>{username}</username>
        <url>{url}</url>
        <password>{password}</password>
        <notes>{notes}</notes>
        <uuid>{id}</uuid>
        <image>{icon}</image>
        <creationtime>{created:%Y-%m-%dT%H:%M:%S}</creationtime>
        <lastmodtime>{modified:%Y-%m-%dT%H:%M:%S}</lastmodtime>
        <lastaccesstime>{accessed:%Y-%m-%dT%H:%M:%S}</lastaccesstime>
        <expiretime expires="{expire_valid}">{expires:%Y-%m-%dT%H:%M:%S}</expiretime>
</pwentry>""".format(**entry))
        
        self.obj_root = etree.fromstring(u"""\
<pwlist>
{pwentries}
</pwlist>""".format(pwentries='\n'.join(pwentries)))
        
        return etree.tostring(self.obj_root, pretty_print=True,
                              encoding='utf-8', standalone=True)

    def write_to(self, stream):
        """Serialize the element tree to the out-buffer."""
        if self.out_buffer is None:
            self.out_buffer = io.BytesIO(self.pretty_print())

    def _parse_body(self):
        groups, pos = self._parse_groups(self.in_buffer.getbuffer().tobytes(), self.header.Groups)
        entries = self._parse_entries(self.in_buffer.getbuffer().tobytes(), self.header.Entries, pos, groups)
        return (groups, entries)

    def _parse_groups(self, buf, n_groups):
        pos = 0
        previous_level = 0
        group_stack = []
        groups = []
        group = {}
        while(n_groups):
            m_type = struct.unpack("<H", buf[pos:pos+2])[0]
            pos += 2
            if pos >= len(buf):
                raise ValueError("Group header offset is out of range. ($pos)")
            size = struct.unpack("<L", buf[pos:pos+4])[0]
            pos += 4
            if (pos + size) > len(buf):
                raise ValueError("Group header offset is out of range. ($pos, $size)")
            if (m_type == 1):
                group['group_id'] = struct.unpack("<L", buf[pos:pos+4])[0]
            elif (m_type == 2):
                group['title'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 3):
                group['created'] = self._parse_date(buf, pos, size)
            elif (m_type == 4):
                group['modified'] = self._parse_date(buf, pos, size)
            elif (m_type == 5):
                group['accessed'] = self._parse_date(buf, pos, size)
            elif (m_type == 6):
                group['expires'] = self._parse_date(buf, pos, size)
            elif (m_type == 7):
                group['icon'] = struct.unpack("<L", buf[pos:pos+4])[0]
            elif (m_type == 8):
                group['level'] = struct.unpack("<H", buf[pos:pos+2])[0]
            elif (m_type == 9):
                # flags ignore
                pass
            elif (m_type == 0xFFFF): # end of a group
                n_groups -= 1
                if ('level' in group):
                    level = group['level']
                else:
                    level = 0
                
                if not group_stack:
                    assert level < 1, group
                    group_stack.append(group)
                elif previous_level < level:
                    assert previous_level == level-1, (previous_level, level)
                    group['groups'] = group_stack[-1]['group_id']
                    group_stack.append(group)
                elif previous_level == level:
                    if level > 0:
                        group['groups'] = group_stack[-1]['groups']
                    group_stack[-1] = group
                elif previous_level > level:
                    group_stack[level-previous_level:] = []
                    if level > 0:
                        group['groups'] = group_stack[-1]['groups']
                    group_stack[-1] = group
                previous_level = level
                assert group['level'] <= 0 or 'groups' in group, group
                
                self.groups_by_id[group['group_id']] = group
                groups.append(group)
                group = {}
            else:
                group['unknown_%x'%m_type] = buf[pos:pos+size]
                
            pos += size;

        return groups, pos

    def _parse_entries(self, buf, n_entries, pos, groups):
        entry = {}
        entries = []
        while(n_entries):
            m_type = struct.unpack("<H", buf[pos:pos+2])[0]
            pos += 2;
            if pos >= len(buf):
                raise ValueError("Entry header offset is out of range. ($pos)")
            size = struct.unpack('<L', buf[pos:pos+4])[0]
            pos += 4
            if (pos + size) > len(buf):
                raise ValueError("Entry header offset is out of range. ($pos, $size)" )
            if (m_type == 1):
                entry['id'] = parse_null_turminated(b2a_hex(buf[pos:pos+size]))
            elif (m_type == 2):
                entry['group_id'] = struct.unpack('<L', buf[pos:pos+4])[0]
                entry['group'] = self.groups_by_id[entry['group_id']]['title']
            elif (m_type == 3):
                entry['icon'] = struct.unpack('<L', buf[pos:pos+4])[0]
            elif (m_type == 4):
                entry['title'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 5):
                entry['url'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 6):
                entry['username'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 7):
                entry['password'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 8):
                entry['notes'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 9):
                entry['created'] = self._parse_date(buf, pos, size)
            elif (m_type == 0xA):
                entry['modified'] = self._parse_date(buf, pos, size)
            elif (m_type == 0xB):
                entry['accessed'] = self._parse_date(buf, pos, size)
            elif (m_type == 0xC):
                entry['expires'] = self._parse_date(buf, pos, size)
            elif (m_type == 0xD):
                entry['bin_desc'] = parse_null_turminated(buf[pos:pos+size])
            elif (m_type == 0xE):
                entry['binary'] = buf[pos:pos+size]
            elif (m_type == 0xFFFF): # end of a entry
                n_entries -= 1
                
                # orphaned nodes go into the special group
                if not self._is_group_exists(groups, entry['group_id']):
                    if (not self._is_group_exists(groups, -1)):
                        group = {}
                        group['group_id'] = -1
                        group['title'] = "*Orphaned*"
                        group['icon']    = 0
                        groups.append(group)
                    entry['group_id'] = -1

                if entry['title'] == 'Meta-Info' and entry['username'] == 'SYSTEM' and entry['url'] == '$':
                    if ('notes' in entry and entry['notes'] == 'KPX_GROUP_TREE_STATE'):
                        if (not 'binary' in entry or len(entry['binary']) < 4):
                                raise ValueError("Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error.")
                        n = struct.unpack('<L', entry['binary'][:4])[0]
                        if (n * 5 != len(entry['binary']) - 4):
                            raise ValueError("Discarded metastream KPX_GROUP_TREE_STATE because of a parsing binary error.")
                        else:
                            for i in range(0,n):
                                s = 4+i*5
                                e = 4+i*5 + 4
                                group_id = struct.unpack('<L', entry['binary'][s:e])[0]
                                s = 8+i*5
                                e = 8+i*5 + 1
                                is_expanded = struct.unpack('B', entry['binary'][s:e])[0]
                                for g in groups:
                                    if (g['group_id'] == group_id):
                                        g['expanded'] = is_expanded
                    elif ('notes' in entry and entry['notes'] == 'KPX_CUSTOM_ICONS_4'):
                        if entry['bin_desc'] != 'bin-stream':
                            raise ValueError("Discarded metastream KPX_CUSTOM_ICONS_4 because not a binary stream.")
                        data = entry['binary']
                        if len(data) < 12:
                            raise ValueError("Discarded metastream KPX_CUSTOM_ICONS_4 because format not valid.")
                        
                        # format: https://github.com/keepassx/keepassx/blob/master/src/format/KeePass1Reader.cpp#L855
                        nIcons, nEntries, nGroups = struct.unpack('<LLL', data[:12])
                        ipos = 12
                        for i in range(nIcons):
                            size = struct.unpack('<L', data[ipos:ipos+4])
                            icon = data[ipos+4:ipos+4+size]
                            self.icons.append(dict(id=random.getrandbits(32), data=icon))
                            ipos += size + 4
                        
                        if len(data) < (ipos + (nEntries * 20)):
                            raise ValueError("Custom icon entries truncated.")
                        for i in range(nEntries):
                            entryid = b2a_hex(data[ipos:ipos+16])
                            iconid = struct.unpack('<L', data[ipos+16:ipos+16+4])
                            if entryid in self.entries_by_id:
                                self.entries_by_id[entryid]['icon'] = iconid
                            ipos += 20
                        
                        if len(data) < (ipos + (nGroups * 8)):
                            raise ValueError("Custom icon groups truncated.")
                        for i in range(nEntries):
                            groupid, iconid = struct.unpack('<L', data[ipos:ipos+4+4])
                            if groupid in self.groups_by_id:
                                self.groups_by_id[groupid]['icon'] = iconid
                            ipos += 8
                    elif entry['title'] == 'Meta-Info' and entry['username'] == 'SYSTEM' and entry['url'] == '$':
                        # This is an unparsed metadata entry, save so we can 
                        # parse later
                        self.metainfo.append(entry)
                else:
                    self.entries_by_id[entry['id']] = entry
                    entries.append(entry)
                entry = {}
            else:
                entry['unknown_%x'%m_type] = buf[pos:pos+size]
                
            pos += size;

        return entries

    def _parse_date(self, buf, pos, size):
        b = struct.unpack('<5B', buf[pos:pos+size])
        year = (b[0] << 6) | (b[1] >> 2);
        mon    = ((b[1] & 0b11)         << 2) | (b[2] >> 6);
        day    = ((b[2] & 0b111111) >> 1);
        hour = ((b[2] & 0b1)            << 4) | (b[3] >> 4);
        min    = ((b[3] & 0b1111)     << 2) | (b[4] >> 6);
        sec    = ((b[4] & 0b111111));

        return datetime.datetime(year, mon, day, hour, min, sec)
        # return "%04d-%02d-%02d %02d:%02d:%02d" % (year, mon, day, hour, min, sec)

    def _is_group_exists(self, groups, group_id):
        for g in groups:
            if (g['group_id'] == group_id):
                return True
        return False

    def _get_group_path(self, group_id):
        if 'path' in self.groups_by_id[group_id]:
            return self.groups_by_id[group_id]['path']
        
        group = self.groups_by_id[group_id]
        group_path = [group['title']]
        while 'groups' in group:
            if 'path' in self.groups_by_id[group['groups']]:
                group_path.insert(0, self.groups_by_id[group['groups']]['path'])
                break
            group = self.groups_by_id[group['groups']]
            group_path.insert(0, group['title'])
        gpath = self.groups_by_id[group_id]['path'] = '\\'.join(group_path)
        return gpath


class KDB3Reader(KDB3File, KDBExtension):
    def __init__(self, stream=None, **credentials):
        KDB3File.__init__(self, stream, **credentials)

    def read_from(self, stream):
        KDB3File.read_from(self, stream)
        # the extension requires parsed header and decrypted self.in_buffer, so
        # initialize only here
        KDBExtension.__init__(self)


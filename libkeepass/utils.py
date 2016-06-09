# -*- coding: utf-8 -*-

import sys
import os
import io
import uuid
import base64
import datetime
import codecs

from xml.sax.saxutils import escape
import lxml.etree
import lxml.objectify

import libkeepass.common
import libkeepass.kdb3
import libkeepass.kdb4


def convert_kdb3_to_kxml4(kdb3):
    "Convert given KDB3 to xml in v4 format."
    doc4 = lxml.etree.fromstring(u"""\
<KeePassFile>
    <Meta>
        <Generator>libkeepass (python)</Generator>
        <DatabaseName></DatabaseName>
        <DatabaseNameChanged></DatabaseNameChanged>
        <MemoryProtection>
            <ProtectTitle>False</ProtectTitle>
            <ProtectUserName>False</ProtectUserName>
            <ProtectPassword>True</ProtectPassword>
            <ProtectURL>False</ProtectURL>
            <ProtectNotes>False</ProtectNotes>
        </MemoryProtection>
    </Meta>
    <Root>
    </Root>
</KeePassFile>""")
    
    doc4.find('.//DatabaseName').text = 'converted'
    root = doc4.find('Root')
    
    group_id_map = {}
    root_group = {
        'group_id': 0,
        'title': 'Root',
        'icon': 48,
        'created': datetime.datetime(2999, 12, 28, 23, 59, 59),
        'modified': datetime.datetime(2999, 12, 28, 23, 59, 59),
        'accessed': datetime.datetime(2999, 12, 28, 23, 59, 59),
        'expires': datetime.datetime(2999, 12, 28, 23, 59, 59),
        'expanded': True,
        'level': -1,
    }
    for group in [root_group]+kdb3.groups:
        group = group.copy()
        if group['level'] == 0:
            group['groups'] = 0
        # TODO: Should the uuid be created from the old group_id in some way
        #   to try to provide consistency for multiple conversions of the same
        #   kdb file?  I don't think it should matter for groups, so long as
        #   entries have matching uuids.
        group['uuid'] = base64.b64encode(uuid.uuid4().bytes).decode('ascii')
        group_id_map[group['group_id']] = group['uuid']
        group['expire_valid'] = (group['expires'] != datetime.datetime(2999, 12, 28, 23, 59, 59))
        group['expanded'] = str(bool(group['expanded']))
        
        for k in ('uuid', 'title'):
            group[k] = escape(group[k])
        
        groupEl = lxml.etree.fromstring(u"""\
<Group>
    <UUID>{uuid}</UUID>
    <Name>{title}</Name>
    <IconID>{icon}</IconID>
    <Times>
        <CreationTime>{created:%Y-%m-%dT%H:%M:%S}Z</CreationTime>
        <LastModificationTime>{modified:%Y-%m-%dT%H:%M:%S}Z</LastModificationTime>
        <LastAccessTime>{accessed:%Y-%m-%dT%H:%M:%S}Z</LastAccessTime>
        <ExpiryTime>{expires:%Y-%m-%dT%H:%M:%S}Z</ExpiryTime>
        <Expires>{expire_valid}</Expires>
    </Times>
    <IsExpanded>{expanded}</IsExpanded>
</Group>""".format(**group))
        # FIXME: We assume the v3 timestamps are in UTC, but this is almost
        #   certainly not the case. Perhaps we should allow the user to specify.
        #   Did the old KeePassX always use UTC anyway?  Need to check.
        
        if 'groups' in group:
            # This is a sub-group
            g_parent_uuid = group_id_map[group['groups']]
            root.find(".//Group[UUID='%s']"%g_parent_uuid).append(groupEl)
        else:
            root.append(groupEl)
    
    for entry in kdb3.entries:
        entry = entry.copy()
        entry['uuid'] = escape(base64.b64encode(codecs.decode(entry['id'], 'hex')).decode('ascii'))
        entry['expire_valid'] = (entry['expires'] != datetime.datetime(2999, 12, 28, 23, 59, 59))
        
        entryEl = lxml.etree.fromstring(u"""\
<Entry>
    <UUID>{uuid}</UUID>
    <IconID>{icon}</IconID>
    <Times>
        <CreationTime>{created:%Y-%m-%dT%H:%M:%S}Z</CreationTime>
        <LastModificationTime>{modified:%Y-%m-%dT%H:%M:%S}Z</LastModificationTime>
        <LastAccessTime>{accessed:%Y-%m-%dT%H:%M:%S}Z</LastAccessTime>
        <ExpiryTime>{expires:%Y-%m-%dT%H:%M:%S}Z</ExpiryTime>
        <Expires>{expire_valid}</Expires>
    </Times>
</Entry>""".format(**entry))
        
        for k4 in ('Title', 'URL', 'UserName', 'Password', 'Notes'):
            k3 = k4.lower()
            stringEl = lxml.etree.fromstring(u"""\
<String>
    <Key>{key}</Key>
    <Value>{value}</Value>
</String>""".format(key=k4, value=escape(entry[k3])))
            entryEl.append(stringEl)
        
        if 'bin_desc' in entry and entry['bin_desc']:
            raise ValueError("Unexpected bin_desc '%s'. (%r)"%(entry['bin_desc'], entry.get('binary', '')))
        
        g_parent_uuid = group_id_map[entry['group_id']]
        root.find(".//Group[UUID='%s']"%g_parent_uuid).append(entryEl)
    
    return doc4


def convert_kdb3_to_kdb4(kdb3):
    "Convert given KDB3 file to KDB4."
    # First convert the KDB3 unencrypted binary to xml in v4 format.
    kxml4 = convert_kdb3_to_kxml4(kdb3)
    
    ciphername = kdb3.header.encryption_flags[kdb3.header.Flags-1]
    for cipherid, cname in libkeepass.kdb4.KDB4Header.ciphers.items():
        if ciphername == cname:
            break
    else:
        raise IOError('Unsupported encryption type: %s'%ciphername)
    
    kdb4 = libkeepass.kdb4.KDB4Reader()
    kdb4.header.EndOfHeader = b'\r\n\r\n'
    #~ kdb4.header.Comment = 
    kdb4.header.CipherID = cipherid
    kdb4.header.CompressionFlags = 1 # use compress by default
    kdb4.header.MasterSeed = os.urandom(32)
    # FIXME: This should probably be reset, can it be random???
    kdb4.header.TransformSeed = kdb3.header.MasterSeed2
    kdb4.header.TransformRounds = kdb3.header.KeyEncRounds
    kdb4.header.EncryptionIV = os.urandom(16)
    kdb4.header.ProtectedStreamKey = os.urandom(32)
    kdb4.header.StreamStartBytes = os.urandom(32)
    kdb4.header.InnerRandomStreamID = 2
    
    kdb4.keys = kdb3.keys[:]
    kdb4.in_buffer = io.BytesIO(lxml.etree.tostring(kxml4))
    libkeepass.kdb4.KDBXmlExtension.__init__(kdb4)
    
    return kdb4



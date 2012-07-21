# -*- coding: utf-8 -*-

# file header

from collections import namedtuple

HeaderField = namedtuple('HeaderField', ['raw', 'val'])

class HeaderDict(dict):
    fields = {}
    transform = {}

    def __init__(self, *args):
        dict.__init__(self, args)

    def __getitem__(self, key):
        if isinstance(key, int):
            val = dict.__getitem__(self, key)
        else:
            key = self.fields.get(key)
            if key is None:
                return None
            val =  dict.__getitem__(self, key)
        return val

    def __setitem__(self, key, val):
        func = self.transform.get(key, lambda x: x)
        dict.__setitem__(self, key, HeaderField(val, func(val)))


# file baseclass

import io
from crypto import sha256

class KDBFile:
    def __init__(self, stream=None, **credentials):
        # list of hashed credentials (pre-transformation)
        self.keys = []
        self.add_credentials(**credentials)
        
        # the decrypted/decompressed stream reader
        self.reader = None
        # position into the _buffer where the encrypted data stream begins
        self.header_length = None
        
        # the raw/basic file handle, expect it to be closed after __init__!
        if stream is not None:
            if not isinstance(stream, io.IOBase):
                raise TypeError('Stream does not have the buffer interface.')
            self.read_from(stream)

    def read_from(self, stream):
        # implement parsing/decrypting/etc and finally set self.reader
        pass

    def write_to(self, stream):
        pass

    def add_credentials(self, **credentials):
        if credentials.has_key('password'):
            self.add_key_hash(sha256(credentials['password']))
        if credentials.has_key('keyfile'):
            self.add_key_hash(load_keyfile(credentials['keyfile']))

    def add_key_hash(self, key_hash):
        """
        Add an encryption key hash, can be a hashed password or a hashed
        keyfile. Two things are important: must be SHA256 hashes and sequence is
        important: first password if any, second key file if any.
        """
        if key_hash is not None:
            self.keys.append(key_hash)

    def close(self):
        if self.reader:
            self.reader.close()

    def read(self, n=-1):
        """
        Read the decrypted and uncompressed data. It is XMl data in KDB4.
        
        Note that this is the source data for the lxml.objectify element tree 
        at `self.obj_root`. Any changes made to the parsed element tree will 
        NOT be reflected in that data stream! Use `self.pretty_print` to get
        XML output from the element tree.
        """
        if self.reader:
            return self.reader.read(n)

    def seek(self, offset, whence=io.SEEK_SET):
        if self.reader:
            return self.reader.seek(offset, whence)

    def tell(self):
        if self.reader:
            return self.reader.tell()


# loading keyfiles

import base64
import hashlib
from lxml import etree

def load_keyfile(filename):
    try:
        return load_xml_keyfile(filename)
    except:
        pass
    try:
        return load_plain_keyfile(filename)
    except:
        pass

def load_xml_keyfile(filename):
    """
    // Sample XML file:
    // <?xml version="1.0" encoding="utf-8"?>
    // <KeyFile>
    //     <Meta>
    //         <Version>1.00</Version>
    //     </Meta>
    //     <Key>
    //         <Data>ySFoKuCcJblw8ie6RkMBdVCnAf4EedSch7ItujK6bmI=</Data>
    //     </Key>
    // </KeyFile>
    """
    with open(filename, 'r') as f:
        # ignore meta, currently there is only version "1.00"
        tree = etree.parse(f).getroot()
        # read text from key, data and convert from base64
        return base64.b64decode(tree.find('Key/Data').text)
    raise IOError('Could not parse XML keyfile.')

def load_plain_keyfile(filename):
    """
    A "plain" keyfile is a file containing only the key.
    Any other file (JPEG, MP3, ...) can also be used as keyfile.
    """
    with open(filename, 'rb') as f:
        key = f.read()
        # if the length is 32 bytes we assume it is the key
        if len(key) == 32:
            return key
        # if the length is 64 bytes we assume the key is hex encoded
        if len(key) == 64:
            return key.decode('hex')
        # anything else may be a file to hash for the key
        return sha256(key)
    raise IOError('Could not read keyfile.')

# 

import struct

def stream_unpack(stream, offset, length, typecode='I'):
    if offset is not None:
        stream.seek(offset)
    data = stream.read(length)
    return struct.unpack('<'+typecode, data)[0]

def read_signature(stream):
    sig1 = stream_unpack(stream, 0, 4)
    sig2 = stream_unpack(stream, None, 4)
    #ver_minor = stream_unpack(stream, None, 2, 'h')
    #ver_major = stream_unpack(stream, None, 2, 'h')
    #return (sig1, sig2, ver_major, ver_minor)
    return (sig1, sig2)




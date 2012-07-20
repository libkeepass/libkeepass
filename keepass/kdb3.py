# -*- coding: utf-8 -*-
import io
import uuid
import zlib
import struct
import hashlib
import base64

from crypto import xor, sha256, aes_cbc_decrypt
from crypto import transform_key, unpad

from common import load_keyfile, stream_unpack
from common import KDBFile, HeaderDict


class KDB3Header(HeaderDict):
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

    transform = {
        0: lambda x: struct.unpack('<I', x)[0],
        1: lambda x: x.encode('hex'),
        2: lambda x: x.encode('hex'),
        3: lambda x: x.encode('hex'),
        4: lambda x: struct.unpack('<I', x)[0],
        5: lambda x: struct.unpack('<I', x)[0],
        6: lambda x: x.encode('hex'),
        7: lambda x: x.encode('hex'),
        8: lambda x: struct.unpack('<I', x)[0],
        }

    lengths = [4, 4, 16, 16, 4, 4, 32, 32, 4]

    #TODO how is that field encoded!? it's supposed to be a bitmap, but i get 3.
    encryption_flags = {
        1: 'SHA2',
        #2: 'Rijndael',
        2: 'AES',
        4: 'ArcFour',
        8: 'TwoFish',
        }

class KDB3File(KDBFile):
    def __init__(self, stream, **credentials):
        KDBFile.__init__(self, stream, **credentials)
        
        self.header = KDB3Header()
        
        self._read_header()
        self._decrypt()

    def _read_header(self):
        """
        Parses the header and write the values into self.header. Also sets
        self.header_length.
        """
        # kdb3 has a fixed header length
        self.header_length = 124
        # skip file signature
        self._buffer.seek(8)
        
        field_id = 0
        while True:
            length = self.header.lengths[field_id]
            data = self._read_buffer(None, length, '{}s'.format(length))
            self.header[field_id] = data
            
            field_id += 1
            if field_id > 8:
                break
        
        # this is impossible, as long as noone messes with self.header.lengths
        if self.header_length != self._buffer.tell():
            raise IOError('Unexpected header length! What did you do!?')

    def _decrypt(self):
        if len(self.keys) == 0:
            raise IOError('No credentials found.')
        
        self._make_master_key()
        
        # move read pointer beyond the file header
        if self.header_length is None:
            raise IOError('Header length unknown. Parse the header first!')
        self._buffer.seek(self.header_length)
        
        data = aes_cbc_decrypt(self._buffer.read(), self.master_key, 
            self.header['EncryptionIV'].raw)
        data = unpad(data)
        
        if self.header['ContentHash'].raw == sha256(data):
            self.reader = io.BytesIO(data)
        else:
            raise IOError('Master key invalid.')

    def _make_master_key(self):
        """
        Make the master key by (1) combining the credentials to create 
        a composite hash, (2) transforming the hash using the transform seed
        for a specific number of rounds and (3) finally hashing the result in 
        combination with the master seed.
        """
        #print "masterkey:", ''.join(self.keys).encode('hex')
        #composite = sha256(''.join(self.keys))
        #TODO python-keepass does not support keyfiles, there seems to be a
        # different way to hash those keys in kdb3
        composite = self.keys[0]
        
        tkey = transform_key(composite, 
            self.header['MasterSeed2'].raw, 
            self.header['KeyEncRounds'].val)
        self.master_key = sha256(self.header['MasterSeed'].raw + tkey)


class KDBExtension:
    """
    The KDB3 payload is a ... #TODO ...
    """
    def __init__(self):
        pass

class KDB3Reader(KDB3File, KDBExtension):
    def __init__(self, stream, **credentials):
        KDB3File.__init__(self, stream, **credentials)
        KDBExtension.__init__(self)


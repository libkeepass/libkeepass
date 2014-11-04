# -*- coding: utf-8 -*-
import io
import uuid
import zlib
import struct
import hashlib
import base64

from .crypto import xor, sha256, aes_cbc_decrypt
from .crypto import transform_key, unpad

from .common import load_keyfile, stream_unpack
from .common import KDBFile, HeaderDictionary


KDB3_SIGNATURE = (0x9AA2D903, 0xB54BFB65)


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

    fmt = { 0: '<I', 4: '<I', 5: '<I', 8: '<I' }

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
        
        field_id = 0
        while True:
            length = self.header.lengths[field_id]
            data = stream_unpack(stream, None, length, '{}s'.format(length))
            self.header.b[field_id] = data
            
            field_id += 1
            if field_id > 8:
                break
        
        # this is impossible, as long as noone messes with self.header.lengths
        if self.header_length != stream.tell():
            raise IOError('Unexpected header length! What did you do!?')

    def _decrypt(self, stream):
        super(KDB3File, self)._decrypt(stream)
        
        data = aes_cbc_decrypt(stream.read(), self.master_key, 
            self.header.EncryptionIV)
        data = unpad(data)
        
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
        #print "masterkey:", ''.join(self.keys).encode('hex')
        #composite = sha256(''.join(self.keys))
        #TODO python-keepass does not support keyfiles, there seems to be a
        # different way to hash those keys in kdb3
        composite = self.keys[0]
        tkey = transform_key(composite, 
            self.header.MasterSeed2, 
            self.header.KeyEncRounds)
        self.master_key = sha256(self.header.MasterSeed + tkey)


class KDBExtension:
    """
    The KDB3 payload is a ... #TODO ...
    """
    def __init__(self):
        pass

class KDB3Reader(KDB3File, KDBExtension):
    def __init__(self, stream=None, **credentials):
        KDB3File.__init__(self, stream, **credentials)
        KDBExtension.__init__(self)


# -*- coding: utf-8 -*-
import io
import uuid
import zlib
import struct
import hashlib
import base64


from crypto import xor, sha256, aes_cbc_decrypt
from crypto import transform_key

from common import load_keyfile, stream_unpack

from common import KDBFile, HeaderDict
from reader import HashedBlockReader


KDB4_SALSA20_IV = bytes('e830094b97205d2a'.decode('hex'))


class KDB4Header(HeaderDict):
    fields = {
        'EndOfHeader' : 0,
        'Comment' : 1,
        # cipher used for the data stream after the header
        'CipherID' : 2,
        # indicates whether decrypted data stream is gzip compressed
        'CompressionFlags' : 3,
        # 
        'MasterSeed' : 4,
        # 
        'TransformSeed' : 5,
        # 
        'TransformRounds' : 6,
        # 
        'EncryptionIV' : 7,
        # key used to protect data in xml
        'ProtectedStreamKey' : 8,
        # first 32 bytes of the decrypted data stream after the header
        'StreamStartBytes' : 9,
        # cipher used to protect data in xml (ARC4 or Salsa20)
        'InnerRandomStreamID' : 10,
        }

    transform = {
        #0: lambda x: x,
        #1: lambda x: x,
        2: lambda x: uuid.UUID(bytes=x),
        3: lambda x: struct.unpack('<I', x)[0],
        4: lambda x: x.encode('hex'),
        5: lambda x: x.encode('hex'),
        6: lambda x: struct.unpack('<q', x)[0],
        7: lambda x: x.encode('hex'),
        8: lambda x: x.encode('hex'),
        9: lambda x: x.encode('hex'),
        10: lambda x: x.encode('hex'),
        }

class KDB4File(KDBFile):
    def __init__(self, stream, **credentials):
        KDBFile.__init__(self, stream, **credentials)
        
        self.header = KDB4Header()
        
        self._read_header()
        self._decrypt()

    def _read_header(self):
        """
        Parses the header and write the values into self.header. Also sets
        self.header_length.
        """
        # the first header field starts at byte 12 after the signature
        self._buffer.seek(12)
        
        while True:
            # field_id is a single byte
            field_id = self._read_buffer(None, 1, 'b')
            
            # field_id >10 is undefined
            if not field_id in self.header.fields.values():
                raise IOError('Unknown header field found.')
            
            # two byte (short) length of field data
            length = self._read_buffer(None, 2, 'h')
            if length > 0:
                data = self._read_buffer(None, length, '{}s'.format(length))
                self.header[field_id] = data
            
            # set position in data stream of end of header
            if field_id == 0:
                self.header_length = self._buffer.tell()
                break

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
        
        length = len(self.header['StreamStartBytes'].raw)
        if self.header['StreamStartBytes'].raw == data[:length]:
            # skip startbytes and wrap data in a I/O stream inside a block reader
            self.reader = HashedBlockReader(io.BytesIO(data[length:]))
        else:
            raise IOError('Master key invalid.')
        
        if self.header['CompressionFlags'].val == 1:
            d = zlib.decompressobj(16+zlib.MAX_WBITS)
            self.reader = io.BytesIO(d.decompress(self.reader.read()))

    def _make_master_key(self):
        """
        Make the master key by (1) combining the credentials to create 
        a composite hash, (2) transforming the hash using the transform seed
        for a specific number of rounds and (3) finally hashing the result in 
        combination with the master seed.
        """
        composite = sha256(''.join(self.keys))
        tkey = transform_key(composite, 
            self.header['TransformSeed'].raw, 
            self.header['TransformRounds'].val)
        self.master_key = sha256(self.header['MasterSeed'].raw + tkey)


from lxml import etree
from lxml import objectify
from crypto import Salsa20

class KDBXmlExtension:
    """
    The KDB4 payload is a XML document. For easier use this class provides
    a lxml.objectify'ed version of the XML-tree as the `obj_root` attribute.
    
    More importantly though in the XML document text values can be protected
    using Salsa20. Protected elements are unprotected by default (passwords are
    in clear). You can override this with the `unprotect=False` argument.
    """
    def __init__(self, unprotect=True):
        self._salsa_buffer = bytearray()
        self.reader.seek(0)
        self.obj_root = objectify.parse(self.reader).getroot()
        # create salsa20 instance with hashed key and fixed iv
        self.salsa = Salsa20(sha256(self.header['ProtectedStreamKey'].raw), 
            KDB4_SALSA20_IV)
        if unprotect:
            self.unprotect()

    def unprotect(self):
        """
        Find all elements with a 'Protected=True' attribute and replace the text
        with an unprotected value in the XML element tree. The original text is
        set as 'ProtectedValue' attribute and the 'Protected' attribute is set
        to 'False'. The 'ProtectPassword' element in the 'Meta' section is also
        set to 'False'.
        """
        self._reset_salsa()
        self.obj_root.Meta.MemoryProtection.ProtectPassword._setText('False')
        for elem in self.obj_root.iterfind('.//Value[@Protected="True"]'):
            elem.set('ProtectedValue', elem.text)
            elem.set('Protected', 'False')
            elem._setText(self._unprotect(elem.text))

    def protect(self):
        """
        Find all elements with a 'Protected=False' attribute and replace the
        text with a protected value in the XML element tree. If there was a
        'ProtectedValue' attribute, it is deleted and the 'Protected' attribute
        is set to 'True'. The 'ProtectPassword' element in the 'Meta' section is
        also set to 'True'.
        
        This does not just restore the previous protected value, but reencrypts
        all text values of elements with 'Protected=False'. So you could use
        this after modifying a password, adding a completely new entry or
        deleting entry history items.
        """
        self._reset_salsa()
        self.obj_root.Meta.MemoryProtection.ProtectPassword._setText('True')
        for elem in self.obj_root.iterfind('.//Value[@Protected="False"]'):
            etree.strip_attributes(elem, 'ProtectedValue')
            elem.set('Protected', 'True')
            elem._setText(self._protect(elem.text))

    def pretty_print(self):
        """Return a serialization of the element tree."""
        return etree.tostring(self.obj_root, pretty_print=True)

    def _reset_salsa(self):
        """Clear the salsa buffer and reset algorithm counter to 0."""
        self._salsa_buffer = bytearray()
        self.salsa.setCounter(0)

    def _get_salsa(self, length):
        """
        Returns the next section of the "random" Salsa20 bytes with the 
        requested `length`.
        """
        if length > len(self._salsa_buffer):
            new_salsa = self.salsa.encryptBytes(str(bytearray(64)))
            self._salsa_buffer.extend(new_salsa)
        nacho = self._salsa_buffer[:length]
        del self._salsa_buffer[:length]
        return nacho

    def _unprotect(self, string):
        """
        Base64 decode and XOR the given `string` with the next salsa.
        Returns an unprotected string.
        """
        tmp = base64.b64decode(string)
        return str(xor(tmp, self._get_salsa(len(tmp))))

    def _protect(self, string):
        """
        XORs the given `string` with the next salsa and base64 encodes it.
        Returns a protected string.
        """
        tmp = str(xor(string, self._get_salsa(len(string))))
        return base64.b64encode(tmp)

class KDB4Reader(KDB4File, KDBXmlExtension):
    def __init__(self, stream, **credentials):
        KDB4File.__init__(self, stream, **credentials)
        KDBXmlExtension.__init__(self)


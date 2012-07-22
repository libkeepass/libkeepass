# -*- coding: utf-8 -*-
import os, sys
import unittest

from keepass.crypto import sha256, transform_key, aes_cbc_decrypt, xor

class TextCrypto(unittest.TestCase):
    def test_sha256(self):
        self.assertEquals(sha256(''), 
            "\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA" \
            "\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U")
        self.assertEquals(len(sha256('')), 32)
        self.assertEquals(len(sha256('asdf')), 32)

    def test_transform_key(self):
        self.assertEquals(transform_key(sha256('a'), sha256('b'), 1), 
            '"$\xe6\x83\xb7\xbf\xa9|\x82W\x01J\xce=\xaa\x8d{\x18\x99|0\x1f' \
            '\xbbLT4"F\x83\xd0\xc8\xf9')
        self.assertEquals(transform_key(sha256('a'), sha256('b'), 2000), 
            '@\xe5Y\x98\xf7\x97$\x0b\x91!\xbefX\xe8\xb6\xbb\t\xefX>\xb3E\x85' \
            '\xedz\x15\x9c\x96\x03K\x8a\xa1')

    def test_aes_cbc_decrypt(self):
        self.assertEquals(aes_cbc_decrypt('datamustbe16byte', sha256('b'), 
            'ivmustbe16bytesl'), 
            'x]\xb5\xa6\xe3\x10\xf4\x88\x91_\x03\xc6\xb9\xfb`)')
        self.assertEquals(aes_cbc_decrypt('datamustbe16byte', sha256('c'), 
            'ivmustbe16bytesl'), 
            '\x06\x91 \xd9\\\xd8\x14\xa0\xdc\xd7\x82\xa0\x92\xfb\xe8l')

    def test_xor(self):
        self.assertEquals(xor('', ''), '')
        self.assertEquals(xor('\x00', '\x00'), '\x00')
        self.assertEquals(xor('\x01', '\x00'), '\x01')
        self.assertEquals(xor('\x01\x01', '\x00\x01'), '\x01\x00')
        self.assertEquals(xor('banana', 'ananas'), '\x03\x0f\x0f\x0f\x0f\x12')

import keepass

class TestModule(unittest.TestCase):

    def test_get_kdb_class(self):
        # v3
        self.assertIsNotNone(keepass.get_kdb_reader([0x9AA2D903, 0xB54BFB65]))
        self.assertEquals(keepass.get_kdb_reader([0x9AA2D903, 0xB54BFB65]), 
            keepass.kdb3.KDB3Reader)
        # v4
        self.assertIsNotNone(keepass.get_kdb_reader([0x9AA2D903, 0xB54BFB67]))
        self.assertEquals(keepass.get_kdb_reader([0x9AA2D903, 0xB54BFB67]), 
            keepass.kdb4.KDB4Reader)
        
        # mythical pre2.x signature
        with self.assertRaisesRegexp(IOError, "Unknown sub signature."):
            keepass.get_kdb_reader([0x9AA2D903, 0xB54BFB66, 3, 0])
        
        # unknown sub signature
        with self.assertRaisesRegexp(IOError, "Unknown sub signature."):
            keepass.get_kdb_reader([0x9AA2D903, 0xB54BFB60, 3, 0])
        # valid sub signature, unknown base signature
        with self.assertRaisesRegexp(IOError, "Unknown base signature."):
            keepass.get_kdb_reader([0x9AA2D900, 0xB54BFB65, 3, 0])
        # unknown sub signature, unknown base signature
        with self.assertRaisesRegexp(IOError, "Unknown base signature."):
            keepass.get_kdb_reader([0x9AA2D900, 0xB54BFB60, 3, 0])

class TestCommon(unittest.TestCase):

    def test_header_dict(self):
        h = keepass.common.HeaderDict()
        h[1] = "eins"
        self.assertEquals(h[1].raw, "eins")
        self.assertEquals(h[1].val, "eins")
        h.fields['first'] = 1
        self.assertEquals(h['first'].raw, "eins")
        self.assertEquals(h['first'].val, "eins")
        h[2] = "zwei"
        h.fields['second'] = 2
        self.assertEquals(h['second'].raw, "zwei")
        self.assertEquals(h['second'].val, "zwei")
        self.assertRaises(KeyError, h['third'])
        #self.assertRaises(KeyError, h[3])

# created with KeePassX 0.4.3
absfile2 = os.path.abspath('tests/sample7_kpx.kdb')
# created with KeePass 2.19 on linux
filename1 = 'sample1.kdbx'
absfile1 = os.path.abspath('tests/'+filename1)
absfile3 = os.path.abspath('tests/sample2.kdbx')
keyfile3 = os.path.abspath('tests/sample2_keyfile.key')
absfile4 = os.path.abspath('tests/sample3.kdbx')
keyfile4 = os.path.abspath('tests/sample3_keyfile.exe')
absfile5 = os.path.abspath('tests/sample4.kdbx')
keyfile5 = os.path.abspath('tests/sample3_keyfile.exe')

output1 = os.path.abspath('tests/output1.kdbx')
output4 = os.path.abspath('tests/output4.kdbx')


class TestKDB4(unittest.TestCase):

    def test_class_interface(self):
        """Test direct KDB4Reader class usage"""
        kdb = keepass.KDB4Reader()
        with self.assertRaisesRegexp(TypeError, "Stream does not have the buffer interface."):
            kdb.read_from(absfile1)
        with self.assertRaisesRegexp(IOError, "No credentials found."):
            with open(absfile1, 'rb') as fh:
                kdb.read_from(fh)
        kdb.add_credentials(password='asdf')
        with open(absfile1, 'rb') as fh:
            kdb.read_from(fh)
        self.assertEquals(kdb.read(32), '<?xml version="1.0" encoding="ut')

    def test_write_file(self):
        # valid password and plain keyfile, compressed kdb
        with keepass.open(absfile1, password="asdf") as kdb:
            with open(output1, 'w') as outfile:
                kdb.write_to(outfile)
        with keepass.open(output1, password="asdf") as kdb:
            self.assertEquals(kdb.read(32), '<?xml version="1.0" encoding="ut')

        with keepass.open(absfile4, password="qwer", keyfile=keyfile4) as kdb:
            with open(output4, 'w') as outfile:
                kdb.write_to(outfile)
        with keepass.open(output4, password="qwer", keyfile=keyfile4) as kdb:
            self.assertEquals(kdb.read(32), '<?xml version="1.0" encoding="ut')

    def test_open_file(self):
        # file not found, proper exception gets re-raised
        with self.assertRaisesRegexp(IOError, "No such file or directory"):
            with keepass.open(filename1, password="asdf"):
                pass
        # invalid password
        with self.assertRaisesRegexp(IOError, "No credentials found."):
            with keepass.open(absfile1):
                pass
        # invalid password
        with self.assertRaisesRegexp(IOError, "Master key invalid."):
            with keepass.open(absfile1, password="invalid"):
                pass
        # invalid keyfile
        with self.assertRaisesRegexp(IOError, "Master key invalid."):
            with keepass.open(absfile1, password="invalid", keyfile="invalid"):
                pass

        # old kdb file
        with keepass.open(absfile2, password="asdf") as kdb:
            self.assertIsNotNone(kdb)

        # valid password
        with keepass.open(absfile1, password="asdf") as kdb:
            self.assertIsNotNone(kdb)
            self.assertIsInstance(kdb, keepass.kdb4.KDB4Reader)


        # valid password and xml keyfile
        with keepass.open(absfile3, password="asdf", keyfile=keyfile3) as kdb:
            self.assertIsNotNone(kdb)
            self.assertIsInstance(kdb, keepass.kdb4.KDB4Reader)

        # valid password and plain keyfile, compressed kdb
        with keepass.open(absfile4, password="qwer", keyfile=keyfile4) as kdb:
            self.assertIsNotNone(kdb)
            self.assertIsInstance(kdb, keepass.kdb4.KDB4Reader)
            
            # read raw data
            tmp1 = kdb.read(32)
            tmp2 = kdb.read(32)
            self.assertIsNotNone(tmp1)
            self.assertEquals(tmp1, '<?xml version="1.0" encoding="ut')
            self.assertIsNotNone(tmp2)
            self.assertEquals(tmp2, 'f-8" standalone="yes"?>\n<KeePass')
            self.assertNotEquals(tmp1, tmp2)
            self.assertEquals(kdb.tell(), 64)
            kdb.seek(0)
            tmp3 = kdb.read(32)
            self.assertEquals(tmp1, tmp3)
            self.assertNotEquals(tmp2, tmp3)

            # read xml
            xml1 = kdb.obj_root.Root.Group.Entry.String[1].Value
            self.assertEquals(xml1, "Password")
            xml2 = kdb.obj_root.Root.Group.Entry.String[1].Value.get('ProtectedValue')
            kdb.protect() # re-encrypt protected values again
            xml3 = kdb.obj_root.Root.Group.Entry.String[1].Value
            self.assertEquals(xml2, xml3)
            kdb.unprotect() # and make passwords clear again
            xml4 = kdb.obj_root.Root.Group.Entry.String[1].Value
            self.assertEquals(xml1, xml4)

            self.assertIsNotNone(kdb.pretty_print())

#        # valid password and plain keyfile, uncompressed kdb
#        with keepass.open(absfile5, password="qwer", keyfile=keyfile5) as kdb:
#            self.assertIsNotNone(kdb)
#            self.assertIsInstance(kdb, keepass.kdb4.KDB4Reader)
#            
#            # read raw data
#            tmp1 = kdb.read()
#            tmp2 = kdb.read()
#            self.assertIsNotNone(tmp1)
#            self.assertIsNotNone(tmp2)
#            self.assertNotEquals(tmp1, tmp2)
#            self.assertEquals(kdb.tell(), 64)
#            kdb.seek(0)
#            tmp3 = kdb.read(32)
#            self.assertEquals(tmp1, tmp3)
#            self.assertNotEquals(tmp2, tmp3)

#            # read xml
#            xml1 = kdb.obj_root.Root.Group.Entry.String[1].Value
#            self.assertEquals(xml1, "Password")
#            xml2 = kdb.obj_root.Root.Group.Entry.String[1].Value.get('ProtectedValue')
#            kdb.protect() # re-encrypt protected values again
#            xml3 = kdb.obj_root.Root.Group.Entry.String[1].Value
#            self.assertEquals(xml2, xml3)
#            kdb.unprotect() # and make passwords clear again
#            xml4 = kdb.obj_root.Root.Group.Entry.String[1].Value
#            self.assertEquals(xml1, xml4)

#            self.assertIsNotNone(kdb.pretty_print())






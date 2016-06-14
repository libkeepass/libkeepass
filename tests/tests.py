# -*- coding: utf-8 -*-
import os
import sys
import unittest

import libkeepass
import libkeepass.common
import libkeepass.kdb4
import libkeepass.kdb3


sys.path.append(os.path.abspath("."))
sys.path.append(os.path.abspath(".."))

from libkeepass.crypto import sha256, transform_key, aes_cbc_decrypt, xor, pad
from libkeepass.crypto import AES_BLOCK_SIZE


class TextCrypto(unittest.TestCase):
    def test_sha256(self):
        self.assertEquals(sha256(b''),
                          b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA"
                          b"\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U")
        self.assertEquals(len(sha256(b'')), 32)
        self.assertEquals(len(sha256(b'asdf')), 32)

    def test_transform_key(self):
        self.assertEquals(transform_key(sha256(b'a'), sha256(b'b'), 1),
                          b'"$\xe6\x83\xb7\xbf\xa9|\x82W\x01J\xce=\xaa\x8d{\x18\x99|0\x1f'
                          b'\xbbLT4"F\x83\xd0\xc8\xf9')
        self.assertEquals(transform_key(sha256(b'a'), sha256(b'b'), 2000),
                          b'@\xe5Y\x98\xf7\x97$\x0b\x91!\xbefX\xe8\xb6\xbb\t\xefX>\xb3E\x85'
                          b'\xedz\x15\x9c\x96\x03K\x8a\xa1')

    def test_aes_cbc_decrypt(self):
        self.assertEquals(aes_cbc_decrypt(b'datamustbe16byte', sha256(b'b'),
                                          b'ivmustbe16bytesl'),
                          b'x]\xb5\xa6\xe3\x10\xf4\x88\x91_\x03\xc6\xb9\xfb`)')
        self.assertEquals(aes_cbc_decrypt(b'datamustbe16byte', sha256(b'c'),
                                          b'ivmustbe16bytesl'),
                          b'\x06\x91 \xd9\\\xd8\x14\xa0\xdc\xd7\x82\xa0\x92\xfb\xe8l')

    def test_xor(self):
        self.assertEquals(xor(b'', b''), b'')
        self.assertEquals(xor(b'\x00', b'\x00'), b'\x00')
        self.assertEquals(xor(b'\x01', b'\x00'), b'\x01')
        self.assertEquals(xor(b'\x01\x01', b'\x00\x01'), b'\x01\x00')
        self.assertEquals(xor(b'banana', b'ananas'), b'\x03\x0f\x0f\x0f\x0f\x12')

    def test_pad(self):
        self.assertEquals(pad(b''), b'\x10' * 16)
        self.assertEquals(pad(b'\xff'), b'\xff' + b'\x0f' * 15)
        self.assertEquals(pad(b'\xff' * 2), b'\xff' * 2 + b'\x0e' * 14)
        self.assertEquals(pad(b'\xff' * 3), b'\xff' * 3 + b'\x0d' * 13)
        self.assertEquals(pad(b'\xff' * 4), b'\xff' * 4 + b'\x0c' * 12)
        self.assertEquals(pad(b'\xff' * 5), b'\xff' * 5 + b'\x0b' * 11)
        self.assertEquals(len(pad(b'\xff')), AES_BLOCK_SIZE)
        self.assertEquals(len(pad(b'\xff' * 0)), AES_BLOCK_SIZE)
        self.assertEquals(len(pad(b'\xff' * 1)), AES_BLOCK_SIZE)
        self.assertEquals(len(pad(b'\xff' * 2)), AES_BLOCK_SIZE)
        self.assertEquals(len(pad(b'\xff' * 15)), AES_BLOCK_SIZE)
        self.assertEquals(len(pad(b'\xff' * 16)), 2 * AES_BLOCK_SIZE)
        self.assertEquals(len(pad(b'\xff' * 17)), 2 * AES_BLOCK_SIZE)


class TestModule(unittest.TestCase):
    def test_get_kdb_class(self):
        # v3
        self.assertIsNotNone(libkeepass.get_kdb_reader([0x9AA2D903, 0xB54BFB65]))
        self.assertEquals(libkeepass.get_kdb_reader([0x9AA2D903, 0xB54BFB65]), libkeepass.kdb3.KDB3Reader)
        # v4
        self.assertIsNotNone(libkeepass.get_kdb_reader([0x9AA2D903, 0xB54BFB67]))
        self.assertEquals(libkeepass.get_kdb_reader([0x9AA2D903, 0xB54BFB67]), libkeepass.kdb4.KDB4Reader)

        # mythical pre2.x signature
        with self.assertRaisesRegexp(IOError, "Unknown sub signature."):
            libkeepass.get_kdb_reader([0x9AA2D903, 0xB54BFB66, 3, 0])

        # unknown sub signature
        with self.assertRaisesRegexp(IOError, "Unknown sub signature."):
            libkeepass.get_kdb_reader([0x9AA2D903, 0xB54BFB60, 3, 0])
        # valid sub signature, unknown base signature
        with self.assertRaisesRegexp(IOError, "Unknown base signature."):
            libkeepass.get_kdb_reader([0x9AA2D900, 0xB54BFB65, 3, 0])
        # unknown sub signature, unknown base signature
        with self.assertRaisesRegexp(IOError, "Unknown base signature."):
            libkeepass.get_kdb_reader([0x9AA2D900, 0xB54BFB60, 3, 0])


class TestCommon(unittest.TestCase):
    def test_header_dict(self):
        h = libkeepass.common.HeaderDictionary()
        # configure fields
        h.fields = {'first': 1, 'second': 2}

        # set and get via int or name
        h[1] = '1_eins'
        self.assertEquals(h[1], '1_eins')
        self.assertEquals(h['first'], '1_eins')
        h['first'] = '2_eins'
        self.assertEquals(h[1], '2_eins')
        self.assertEquals(h['first'], '2_eins')

        # in fields, but not set
        self.assertRaises(KeyError, lambda: h[2])
        self.assertRaises(KeyError, lambda: h['second'])

        # not even in fields
        self.assertRaises(KeyError, lambda: h[3])
        self.assertRaises(KeyError, lambda: h['third'])

        # attribute access (reading)
        self.assertEquals(h.first, '2_eins')
        self.assertRaises(AttributeError, lambda: h.second)
        self.assertRaises(AttributeError, lambda: h.third)

        # attribute writing
        h.first = '3_eins'
        self.assertEquals(h.first, '3_eins')
        h.second = '1_zwei'
        self.assertEquals(h.second, '1_zwei')
        self.assertEquals(h[2], '1_zwei')
        self.assertEquals(h['second'], '1_zwei')

        # add another field and data
        h.fields['third'] = 3
        h.third = '1_drei'
        self.assertEquals(h.third, '1_drei')
        self.assertEquals(h[3], '1_drei')
        self.assertEquals(h['third'], '1_drei')
        h['third'] = '2_drei'
        self.assertEquals(h.third, '2_drei')
        self.assertEquals(h[3], '2_drei')
        self.assertEquals(h['third'], '2_drei')

        # implicit nice to raw conversion
        h.fields['rounds'] = 4
        h.fmt[4] = '<q'
        h[4] = 3000
        self.assertEquals(h.rounds, 3000)
        self.assertEquals(h.b.rounds, b'\xb8\x0b\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b['rounds'], b'\xb8\x0b\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b[4], b'\xb8\x0b\x00\x00\x00\x00\x00\x00')
        h['rounds'] = 3001
        self.assertEquals(h.rounds, 3001)
        self.assertEquals(h.b.rounds, b'\xb9\x0b\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b['rounds'], b'\xb9\x0b\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b[4], b'\xb9\x0b\x00\x00\x00\x00\x00\x00')
        h.rounds = 3002
        self.assertEquals(h.rounds, 3002)
        self.assertEquals(h.b.rounds, b'\xba\x0b\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b['rounds'], b'\xba\x0b\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b[4], b'\xba\x0b\x00\x00\x00\x00\x00\x00')

        h.b[4] = b'\x70\x17\x00\x00\x00\x00\x00\x00'
        self.assertEquals(h.rounds, 6000)
        self.assertEquals(h.b.rounds, b'\x70\x17\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b['rounds'], b'\x70\x17\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b[4], b'\x70\x17\x00\x00\x00\x00\x00\x00')
        h.b['rounds'] = b'\x71\x17\x00\x00\x00\x00\x00\x00'
        self.assertEquals(h.rounds, 6001)
        self.assertEquals(h.b.rounds, b'\x71\x17\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b['rounds'], b'\x71\x17\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b[4], b'\x71\x17\x00\x00\x00\x00\x00\x00')
        h.b.rounds = b'\x72\x17\x00\x00\x00\x00\x00\x00'
        self.assertEquals(h.rounds, 6002)
        self.assertEquals(h.b.rounds, b'\x72\x17\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b['rounds'], b'\x72\x17\x00\x00\x00\x00\x00\x00')
        self.assertEquals(h.b[4], b'\x72\x17\x00\x00\x00\x00\x00\x00')

        # raw interface without conversation
        h.fields['hash'] = 5
        h.hash = b'\x91.\xc8\x03\xb2\xceI\xe4\xa5A\x06\x8dIZ'
        self.assertEquals(h.hash, b'\x91.\xc8\x03\xb2\xceI\xe4\xa5A\x06\x8dIZ')
        self.assertEquals(h.b.hash, b'\x91.\xc8\x03\xb2\xceI\xe4\xa5A\x06\x8dIZ')
        # assert False

# created with KeePassX 0.4.3
absfile2 = os.path.abspath('tests/sample7_kpx.kdb')
# created with KeePass 2.19 on linux
absfile1 = os.path.abspath('tests/sample1.kdbx')
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
        kdb = libkeepass.kdb4.KDB4Reader()
        with self.assertRaisesRegexp(TypeError, "Stream does not have the buffer interface."):
            kdb.read_from(absfile1)
        with self.assertRaisesRegexp(IndexError, "No credentials found."):
            with open(absfile1, 'rb') as fh:
                kdb.read_from(fh)
        kdb.add_credentials(password='asdf')
        with open(absfile1, 'rb') as fh:
            kdb.read_from(fh)
        self.assertEquals(kdb.opened, True)
        self.assertEquals(kdb.read(32), b'<?xml version="1.0" encoding="ut')

    def test_write_file(self):
        # valid password and plain keyfile, compressed kdb
        with libkeepass.open(absfile1, password="asdf") as kdb:
            self.assertEquals(kdb.opened, True)
            self.assertEquals(kdb.read(32), b'<?xml version="1.0" encoding="ut')
            kdb.set_compression(0)
            # kdb.set_comment("this is pretty cool!")
            kdb.clear_credentials()
            kdb.add_credentials(password="yxcv")
            with open(output1, 'wb') as outfile:
                kdb.write_to(outfile)
        with libkeepass.open(output1, password="yxcv") as kdb:
            self.assertEquals(kdb.read(32), b"<?xml version='1.0' encoding='ut")

        with libkeepass.open(absfile4, password="qwer", keyfile=keyfile4) as kdb:
            self.assertEquals(kdb.opened, True)
            self.assertEquals(kdb.read(32), b'<?xml version="1.0" encoding="ut')
            with open(output4, 'wb') as outfile:
                kdb.write_to(outfile)
        with libkeepass.open(output4, password="qwer", keyfile=keyfile4) as kdb:
            self.assertEquals(kdb.read(32), b"<?xml version='1.0' encoding='ut")

    def test_open_file(self):
        # file not found, proper exception gets re-raised
        with self.assertRaisesRegexp(IOError, "No such file or directory"):
            with libkeepass.open(absfile1 + '.invalid', password="asdf"):
                pass
        # invalid password
        with self.assertRaisesRegexp(IndexError, "No credentials found."):
            with libkeepass.open(absfile1):
                pass
        # invalid password
        with self.assertRaisesRegexp(IOError, "Master key invalid."):
            with libkeepass.open(absfile1, password="invalid"):
                pass
        # invalid keyfile
        with self.assertRaisesRegexp(IOError, "Master key invalid."):
            with libkeepass.open(absfile1, password="invalid", keyfile="invalid"):
                pass

        # old kdb file
        with libkeepass.open(absfile2, password="asdf") as kdb:
            self.assertIsNotNone(kdb)
            self.assertEquals(kdb.opened, True)

        # valid password
        with libkeepass.open(absfile1, password="asdf") as kdb:
            self.assertIsNotNone(kdb)
            self.assertEquals(kdb.opened, True)
            self.assertIsInstance(kdb, libkeepass.kdb4.KDB4Reader)

        # valid password and xml keyfile
        with libkeepass.open(absfile3, password="asdf", keyfile=keyfile3) as kdb:
            self.assertIsNotNone(kdb)
            self.assertEquals(kdb.opened, True)
            self.assertIsInstance(kdb, libkeepass.kdb4.KDB4Reader)

        # valid password and plain keyfile, compressed kdb
        with libkeepass.open(absfile4, password="qwer", keyfile=keyfile4) as kdb:
            self.assertIsNotNone(kdb)
            self.assertEquals(kdb.opened, True)
            self.assertIsInstance(kdb, libkeepass.kdb4.KDB4Reader)

            # read raw data
            tmp1 = kdb.read(32)
            tmp2 = kdb.read(32)
            self.assertIsNotNone(tmp1)
            self.assertEquals(tmp1, b'<?xml version="1.0" encoding="ut')
            self.assertIsNotNone(tmp2)
            self.assertEquals(tmp2, b'f-8" standalone="yes"?>\n<KeePass')
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
            kdb.protect()  # re-encrypt protected values again
            xml3 = kdb.obj_root.Root.Group.Entry.String[1].Value
            self.assertEquals(xml2, xml3)
            kdb.unprotect()  # and make passwords clear again
            xml4 = kdb.obj_root.Root.Group.Entry.String[1].Value
            self.assertEquals(xml1, xml4)

            self.assertIsNotNone(kdb.pretty_print())

# # valid password and plain keyfile, uncompressed kdb
# with libkeepass.open(absfile5, password="qwer", keyfile=keyfile5) as kdb:
# self.assertIsNotNone(kdb)
# self.assertIsInstance(kdb, libkeepass.kdb4.KDB4Reader)
#
# # read raw data
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

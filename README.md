libkeepass
==========

Python module to read KeePass 1.x/KeePassX (v3) and KeePass 2.x (v4) files.

Warning
-------

"this code makes no attempt to secure its memory"

Requirements
------------

see requirements.txt

KeePass 1.x support
-------------------

The v3 reader will parse the v3 binary format and put groups into the "groups"
attribute, and entries into the "entries" attribute. The special icon entry is
parsed and icons can be accessed via the "icons" attribute. Other special
entries are not parsed and seen as regular entries.

Only passwords are supported.

No write support.

KeePass 2.x support
-------------------

The v4 reader can output the decrypted XML document that file format is based
on. It is also available as parsed objectified element tree.

The password elements in the XML document are protected in addition to the AES
encryption of the whole database. Switching between clear text and protected is
possible.

Passwords and key-file protection is supported.

Compressed and uncompressed files are supported.

There is basic "save as" write support. When writing the KeePass2 file, the
element tree is protected, serialized, compressed and encrypted according to the
settings in the file header and written to a stream.

Examples
--------

    import libkeepass

    filename = "input.kdbx"
    with libkeepass.open(filename, password='secret', keyfile='putty.exe') as kdb:
        # print parsed element tree as xml
        print kdb.pretty_print()

        # re-encrypt the password fields
        kdb.protect()
        print kdb.pretty_print()

        # or use kdb.obj_root to access the element tree
        kdb.obj_root.findall('.//Entry')

        # change the master password before writing
        kdb.clear_credentials()
        kdb.add_credentials(password="m04r_s3cr37")

        # disable compression
        kdb.set_compression(0)

        # write to a new file
        with open('output', 'wb') as output:
            kdb.write_to(output)

Testing
-------

Make a virtualenv and install the requirements. Then run the tests script::

    pip install -r requirements.txt
    nosetests tests/tests.py


References
----------

Initially Brett Viren's code was a starting point and some of his code is being
re-used unchanged (https://github.com/brettviren/python-keepass).

For v4 support reading the original Keepass2 C# source was used as inspiration
(http://keepass.info).

Keepass 2.x uses Salsa20 to protect data in XML. Currently puresalsa20 is used
(http://www.tiac.net/~sw/2010/02/PureSalsa20/index.html) and included.

For v3 read support, code was copied with some enhancements from WAKAYAMA
Shirou's kptool  (see: https://github.com/shirou/kptool)

Thanks to them and all others who came before are in order.

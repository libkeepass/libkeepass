libkeepass
==========

Low-level Python (2.7/3.x) module to read KeePass 1.x/KeePassX (v3) and KeePass 2.x (v4)
files.

See `pykeepass`_ or `kppy`_ for higher level database access and editing.

.. _`pykeepass`: https://github.com/pschmitt/pykeepass
.. _`kppy`: https://github.com/raymontag/kppy

Warning
-------

This code makes no attempt to secure its memory.

Dependencies
-------------

- `pycryptodome`_
- lxml

.. _`pycryptodome`: https://github.com/Legrandin/pycryptodome


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

ChaCha20 database encryption is supported.  However its worth noting that
pycryptodome version 3.6.1 and earlier does not support 12-bytes nonces for
ChaCha20, which we require.  Future versions of pycryptodome do support 12-byte
nonces.  So if you're using 3.6.1 or earlier, decrypting a ChaCha20 encrypted
database will raise an exception.  Decrypting AES and Twofish encrypted
databases will work as normal.

Currently the Argon2 key derivation algorithm and ChaCha20 protected passwords
are unsupported.

Examples
--------

.. code:: python

   import libkeepass

   filename = "input.kdbx"
   with libkeepass.open(filename, password='secret', keyfile='keyfile.key') as kdb:
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
           
   # Alternatively, read a kdb4 file protected
   with libkeepass.open(filename, password='secret', keyfile='keyfile.key', unprotect=False) as kdb:
       # print parsed element tree as xml
       print kdb.pretty_print()

       # decrypt the password fields
       kdb.unprotect()
       print kdb.pretty_print()


Testing
-------

Make a virtualenv and install the requirements (or install through pip). Then run the tests script

.. code:: bash

   pip install -r requirements.txt
   python tests/tests.py

References
----------

Brett Viren's `code`_ was a starting point and some of his code is being
re-used unchanged


For v4 support reading the `original Keepass2 C#`_ source was used as inspiration

Keepass 2.x uses Salsa20 to protect data in XML. Currently `puresalsa20`_ is used and included.


For v3 read support, code was copied with some enhancements from WAKAYAMA
Shirou's `kptool`_.

.. _`original Keepass2 C#`: http://keepass.info
.. _`code`: https://github.com/brettviren/python-keepass
.. _`puresalsa20`: http://www.tiac.net/~sw/2010/02/PureSalsa20/index.html
.. _`kptool`: https://github.com/shirou/kptool)

Thanks to them and all others who came before are in order.

Contributors
------------
- fdemmer
- phpwutz
- nvamilichev
- crass
- pschmitt
- evidlo

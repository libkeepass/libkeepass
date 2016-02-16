**This library is NOT under active development.** I just made a few changes to make a simple KeePass command line password retrieval program (see `samples/query.py`).

If you find this code useful, do not hesitate to fork the repo and make a pull request after your changes are ready. There are no industry-strength solutions for reading and writing both KeePass 1.x & 2.x files in Python (yet). This should change :-)


libkeepass-python3
==================

Python3 module to read KeePass 1.x/KeePassX (v3) and KeePass 2.x (v4) files.

Warning
-------

This code makes **NO ATTEMPT TO SECURE ITS MEMORY**

Installation
------------

Use `setup.py`.

KeePass 1.x support
-------------------

Currently the v3 reader only goes so far, as outputting the raw decrypted data.
Parsing into groups and entries is missing, but probably just needs to be 
integrated from Brett Viren's work.

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

The `samples` directory contains basic samples of using `libkeepass-python3`.

The code below demonstrates some things you can do with `libkeepass-python3` and a KeePass 2.x database:

    import libkeepass
    
    with keepass.open('input.kdbx', password='secret', keyfile='mykey.key') as kdb:
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

Make a virtualenv and install the requirements. Then run the test script:

    python setup.py install
    nosetests tests/tests.py


References
----------

Initially Brett Viren's code was a starting point and some of his code is being
re-used unchanged (see https://github.com/brettviren/python-keepass).

v4 support inspired by the original Keepass2 C# source (http://keepass.info)
was added by Florian Demmer, Lukas Koell and others.

Minimal Python3 support was added by Nikolay Amelichev.

Keepass 2.x uses Salsa20 to protect data in XML. Currently puresalsa20 is used
(http://www.tiac.net/~sw/2010/02/PureSalsa20/index.html) and included.


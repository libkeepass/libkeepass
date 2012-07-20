libkeepass
==========

Python module to read KeePass 1.x/KeePassX (v3) and KeePass 2.x (v4) files.

Warning
-------

"this code makes no attempt to secure its memory"

Requirements
------------

 - PyCrypto

KeePass 1.x support
-------------------

Currently the reader only goes so far, as outputting the raw decrypted data.
Parsing into groups and entries is missing and probably just needs to be 
integrated from Brett Viren's work.

KeePass 2.x support
-------------------

The v4 reader can output the decrypted XML document that format is based on.
It is also available as parsed objectified element tree.

In v4 the password elements are protected in addition to the AES encryption of
the whole document. Protecting and un-protecting again (eg. after modification)
is already supported, but encrypting the whole document not.

The v4 reader supports passwords and key-file protection.

Example
-------

::

    import keepass
    with keepass.open(filename, password='secret', keyfile='putty.exe') as kdb:
        print kdb.pretty_print()
        # or use kdb.obj_root to access the element tree
        # kdb.protect() re-encrypts the password fields

References
----------

Initially Brett Viren's code was a starting point and some of his code is used
in the v3 reader (https://github.com/brettviren/python-keepass).

For v4 support reading the original Keepass2 C# source was used as inspiration
(http://keepass.info).

Keepass 2.x uses Salsa20 to protect data in XML. Currently puresalsa20 is used
(http://www.tiac.net/~sw/2010/02/PureSalsa20/index.html) and included.

Thanks to all others who came before them are in order.


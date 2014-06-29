from setuptools import setup, find_packages

setup(
    name = "libkeepass",
    version = "0.1.2",
    packages = ["libkeepass"],
    author = "Lukas Koell",
    author_email = "phpwutz@gmail.com",
    description = "A library to access keepass v3 (keepass1) and v4 (keepass2) files",
    license = "GPL",
    keywords = "keepass library",
    url = "https://github.com/phpwutz/libkeepass",   # project home page, if any
    install_requires=["lxml==3.2.1", "nose==1.3.0", "pycrypto==2.6.1", "salsa20==0.3.0"],
    test_suite="tests"
)

from setuptools import setup

setup(
    name="libkeepass",
    version="0.1.2",
    packages=["libkeepass"],
    author="Lukas Koell",
    author_email="phpwutz@gmail.com",
    description="A library to access KeePass 1.x/KeePassX (v3) and KeePass "
                "2.x (v4) files",
    license="GPL",
    keywords="keepass library",
    url="https://github.com/phpwutz/libkeepass",  # project home page, if any
    test_suite="tests",
    install_requires=[
        "lxml>=3.2.1",
        "nose>=1.3.0",
        "pycrypto>=2.6.1"
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
    ]
)

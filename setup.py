#!/usr/bin/env python2

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name = 'gulag',
    version = '0.0.1',

    url = 'https://github.com/bhuztez/gulag',
    description = "sandbox for coding contest",

    classifiers = [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 2 :: Only",
        "Topic :: Software Development :: Libraries :: Python Modules"],

    author = 'bhuztez',
    author_email = 'bhuztez@gmail.com',

    packages = ['gulag'],
)

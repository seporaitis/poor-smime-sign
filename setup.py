#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re

from setuptools import setup


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    init_py = open(os.path.join(package, '__init__.py')).read()
    return re.search("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


version = get_version('poor_smime_sign')

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read().replace('.. :changelog:', '')

setup(
    name='poor-smime-sign',
    version='2.0.3',
    description="A very poor tool to do S/MIME signatures on binary files. Probably insecurely.",
    long_description=readme + '\n\n' + history,
    author="Julius Seporaitis",
    author_email='julius@seporaitis.net',
    url='https://github.com/seporaitis/poor-smime-sign',
    packages=[
        'poor_smime_sign',
    ],
    package_dir={'poor_smime_sign':
                 'poor_smime_sign'},
    include_package_data=True,
    install_requires=[],
    license="MIT",
    zip_safe=False,
    keywords='smime sign passbook',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    test_suite='tests',
    tests_require=[]
)

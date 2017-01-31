#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'Click>=6.0',
    'oletools>=0.50',
    'pandas>=0.19.2',
    'scikit-learn>=0.18.1',
    'scipy>=0.18.1',
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='MaliciousMacroBot',
    version='0.1.0',
    description="Malicious Macro Bot: Python module to classify and cluster Microsoft office documents.  Uses machine learning techniques to determine if VBA code is malicious or benign and groups similar documents together.",
    long_description=readme + '\n\n' + history,
    author="Evan Gaustad",
    author_email='evan.gaustad@gmail.com',
    url='https://github.com/egaus/MaliciousMacroBot',
    packages=[
        'MaliciousMacroBot',
    ],
    package_dir={'mmbot':
                 'mmbot'},
    entry_points={
        'console_scripts': [
            'mmbot=mmbot.cli:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="Apache Software License 2.0",
    zip_safe=False,
    keywords='MaliciousMacroBot',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)

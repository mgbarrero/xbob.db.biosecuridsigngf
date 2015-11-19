#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
# Marta Gomez-Barrero <marta.barrero@uam.es>
#
# Copyright (C) 2015 ATVS - Biometric Recognition Group, Universidad Autonoma de Madrid, Spain
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages

# The only thing we do in this file is to call the setup() function with all
# parameters that define our package.
setup(

    name='xbob.db.atvsbiosecureds2signgf',
    version='0.0.1',
    description='ATVS-Biosecure DS2 Signature Global Features Database Access API for Bob',
    url='http://github.com/mgbarrero/xbob.db.atvsbiosecureds2signgf',
    license='GPLv3',
    author='Marta Gomez-Barrero',
    author_email='marta.barrero@uam.es',
    long_description=open('README.rst').read(),

    # This line is required for any distutils based packaging.
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,

    install_requires=[
      'setuptools',
      'six',  # py2/3 compatibility library
      'bob',  # base signal proc./machine learning library
      'xbob.db.verification.utils>=0.1.4' # defines a set of utilities for face verification databases like this one.
    ],

    namespace_packages = [
      'xbob',
      'xbob.db',
      ],

    entry_points={

      # declare database to bob
      'bob.db': [
        'atvskeystroke = xbob.db.atvsbiosecureds2signgf.driver:Interface',
        ],

      # declare tests to bob
      'bob.test': [
        'atvskeystroke = xbob.db.atvsbiosecureds2signgf.test:ATVSBiosecureDS2SignGFDatabaseTest',
        ],

      },

    classifiers = [
      'Development Status :: 4 - Beta',
      'Intended Audience :: Developers',
      'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
      'Natural Language :: English',
      'Programming Language :: Python',
      'Programming Language :: Python :: 3',
      'Topic :: Scientific/Engineering :: Artificial Intelligence',
      'Topic :: Database :: Front-Ends',
      ],
)

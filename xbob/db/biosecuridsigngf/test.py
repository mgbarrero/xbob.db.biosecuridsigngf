#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
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

"""A few checks at the  Biosecure DS2 Signature Global Features database.
"""

import os, sys
import unittest
from .query import Database

class BiosecureDS2SignGFDatabaseTest(unittest.TestCase):

    def test_clients(self):
      db = Database()
      assert len(db.groups()) == 1
      assert len(db.clients()) == 410
      assert len(db.clients(groups='eval')) == 205
      assert len(db.clients(groups='genuine')) == 205
      assert len(db.clients(groups='skilled')) == 205
      assert len(db.models()) == 205
      assert len(db.models(groups='eval')) == 205
      assert len(db.models(groups='genuine')) == 205


    def test_objects(self):
      db = Database()
      assert len(db.objects()) == 8045
      # skilled Forgeries
      assert len(db.objects(protocol='skilledImpostors')) == 8000
      assert len(db.objects(protocol='skilledImpostors', groups='eval')) == 8000
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='enrol')) == 800
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe')) == 7200
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', classes='client')) == 4000
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', classes='skilledImpostor')) == 3200
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1])) == 45
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1], classes='client')) == 25
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1], classes='skilledImpostor')) == 20
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1,2])) == 90
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='client')) == 50
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='skilledImpostor')) == 40
      
      # random Forgeries 
      assert len(db.objects(protocol='randomImpostors')) == 4845
      assert len(db.objects(protocol='randomImpostors', groups='eval')) == 4845
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='enrol')) == 800
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe')) == 4045
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', classes='client')) == 4000
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', classes='randomImpostor')) == 45
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1])) == 70
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1], classes='client')) == 25
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1], classes='randomImpostor')) == 45
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1,2])) == 95
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='client')) == 50
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='randomImpostor')) == 45


    def test_driver_api(self):

      from bob.db.script.dbmanage import main
      assert main('biosecureds2signgf dumplist --self-test'.split()) == 0
      assert main('biosecureds2signgf checkfiles --self-test'.split()) == 0
      assert main('biosecureds2signgf reverse 1_1_genuine --self-test'.split()) == 0
      assert main('biosecureds2signgf path 37 --self-test'.split()) == 0

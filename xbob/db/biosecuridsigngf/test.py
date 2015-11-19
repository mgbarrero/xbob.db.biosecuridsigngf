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

class BiosecurIDSignGFDatabaseTest(unittest.TestCase):

    def test_clients(self):
      db = Database()
      assert len(db.groups()) == 2
      assert len(db.clients()) == 750
      assert len(db.clients(groups='world')) == 50
      assert len(db.clients(groups='eval')) == 350
      assert len(db.clients(groups='genuine')) == 350
      assert len(db.clients(groups='skilled')) == 350
      assert len(db.models()) == 350
      assert len(db.models(groups='eval')) == 350
      assert len(db.models(groups='genuine')) == 350


    def test_objects(self):
      db = Database()
      assert len(db.objects()) == 9250
      # skilled Forgeries
      assert len(db.objects(protocol='skilledImpostors')) == 9200
      assert len(db.objects(protocol='skilledImpostors', groups='world')) == 800
      assert len(db.objects(protocol='skilledImpostors', groups='eval')) == 8400
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='enrol')) == 1200
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe')) == 7200
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', classes='client')) == 3600
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', classes='skilledImpostor')) == 3600
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1])) == 24
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1], classes='client')) == 12
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1], classes='skilledImpostor')) == 12
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1,2])) == 48
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='client')) == 24
      assert len(db.objects(protocol='skilledImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='skilledImpostor')) == 24
      
      # random Forgeries 
      assert len(db.objects(protocol='randomImpostors')) == 5650
      assert len(db.objects(protocol='randomImpostors', groups='world')) == 800
      assert len(db.objects(protocol='randomImpostors', groups='eval')) == 4850
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='enrol')) == 1200
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe')) == 3650
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', classes='client')) == 3600
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', classes='randomImpostor')) == 50
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1])) == 62
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1], classes='client')) == 12
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1], classes='randomImpostor')) == 50
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1,2])) == 74
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='client')) == 24
      assert len(db.objects(protocol='randomImpostors', groups='eval', purposes='probe', model_ids=[1,2], classes='randomImpostor')) == 50


    def test_driver_api(self):

      from bob.db.script.dbmanage import main
      assert main('biosecuridsigngf dumplist --self-test'.split()) == 0
      assert main('biosecuridsigngf checkfiles --self-test'.split()) == 0
      assert main('biosecuridsigngf reverse 1_1_genuine --self-test'.split()) == 0
      assert main('biosecuridsigngf path 37 --self-test'.split()) == 0

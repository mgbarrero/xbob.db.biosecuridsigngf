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

"""Table models and functionality for the BiosecurId database.
"""

import os, numpy
import bob.db.utils
from sqlalchemy import Table, Column, Integer, String, ForeignKey, or_, and_, not_
from bob.db.sqlalchemy_migration import Enum, relationship
from sqlalchemy.orm import backref
from sqlalchemy.ext.declarative import declarative_base

import xbob.db.verification.utils

Base = declarative_base()

protocolPurpose_file_association = Table('protocolPurpose_file_association', Base.metadata,
  Column('protocolPurpose_id', Integer, ForeignKey('protocolPurpose.id')),
  Column('file_id',  Integer, ForeignKey('file.id')))

db_file_extension = '.txt'

class Client(Base):
  """Database clients, marked by an integer identifier and the group they belong to"""

  __tablename__ = 'client'

  # Key identifier for the client
  id = Column(String(100), primary_key=True)
  subid = Column(Integer)
  group_choices = ('world', 'clientEval','impostorEval')
  sgroup = Column(Enum(*group_choices)) # do NOT use group (SQL keyword)
  type_choices = ('genuine', 'skilled')
  stype = Column(Enum(*type_choices)) # do NOT use type

  def __init__(self, id, stype, subid, group):
    self.id = id
    self.stype = stype
    self.subid = subid
    self.sgroup = group

  def __repr__(self):
    return "Client(`%s`, `%s`, `%s`)" % (self.id, self.stype, self.sgroup)


class File(Base, xbob.db.verification.utils.File):
  """Generic file container"""

  __tablename__ = 'file'

  # Key identifier for the file
  id = Column(Integer, primary_key=True)
  # Key identifier of the client associated with this file
  client_id = Column(String(100), ForeignKey('client.id')) # for SQL
  # Unique path to this file inside the database
  path = Column(String(100), unique=True)
  # Session identifier
  session_id = Column(Integer)
  # Shot identifier
  shot_id = Column(Integer)

  # For Python: A direct link to the client object that this file belongs to
  client = relationship("Client", backref=backref("files", order_by=id))

  def __init__(self, client_id, path, session_id, shot_id):
    # call base class constructor
    xbob.db.verification.utils.File.__init__(self, client_id = client_id, path = path)
    
    self.session_id = session_id
    self.shot_id = shot_id


class Protocol(Base):
  """ BiosecurID Signature Global Features protocols"""

  __tablename__ = 'protocol'

  # Unique identifier for this protocol object
  id = Column(Integer, primary_key=True)
  # Name of the protocol associated with this object
  name = Column(String(20), unique=True)

  def __init__(self, name):
    self.name = name

  def __repr__(self):
    return "Protocol('%s')" % (self.name,)


class ProtocolPurpose(Base):
  """ BiosecurID Signature Global Features protocol purposes"""

  __tablename__ = 'protocolPurpose'

  # Unique identifier for this protocol purpose object
  id = Column(Integer, primary_key=True)
  # Id of the protocol associated with this protocol purpose object
  protocol_id = Column(Integer, ForeignKey('protocol.id')) # for SQL
  # Group associated with this protocol purpose object
  group_choices = ('eval',)
  sgroup = Column(Enum(*group_choices))
  # Purpose associated with this protocol purpose object
  purpose_choices = ('enrol', 'probe')
  purpose = Column(Enum(*purpose_choices))

  # For Python: A direct link to the Protocol object that this ProtocolPurpose belongs to
  protocol = relationship("Protocol", backref=backref("purposes", order_by=id))
  # For Python: A direct link to the File objects associated with this ProtcolPurpose
  files = relationship("File", secondary=protocolPurpose_file_association, backref=backref("protocolPurposes", order_by=id))

  def __init__(self, protocol_id, sgroup, purpose):
    self.protocol_id = protocol_id
    self.sgroup = sgroup
    self.purpose = purpose

  def __repr__(self):
    return "ProtocolPurpose('%s', '%s', '%s')" % (self.protocol.name, self.sgroup, self.purpose)


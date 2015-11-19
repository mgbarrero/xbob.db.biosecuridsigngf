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

"""This script creates the BiosecurId database in a single pass.
"""

import os,string

from .models import *

# clients
userid_eval_clients = range(1, 161)
userid_eval_impostors = range(161, 206)

def nodot(item):
  """Can be used to ignore hidden files, starting with the . character."""
  return item[0] != '.'

def add_clients(session, verbose):
  """Add clients to the  Biosecure DS2 Signature Global Features database."""
  users_list = (userid_eval_clients, userid_eval_impostors)
  group_choices = ('clientEval','impostorEval')
  
  for g, group in enumerate(group_choices):
    for ctype in ['genuine', 'skilled']:
      for cdid in users_list[g]:
        cid = ctype + '_%d' % cdid
        if verbose>1: print("  Adding user '%s' of type '%s' group '%s'..." % (cid, ctype, g))
        session.add(Client(cid, ctype, cdid, group))


def add_files(session, imagedir, verbose):
  """Add files to the Biosecure DS2 Signature Global Features database."""

  def add_file(session, basename, userid, shotid, sessionid):
    """Parse a single filename and add it to the list."""
    session.add(File(userid, basename, sessionid, shotid))

  filenames = os.listdir(imagedir)
  for filename in filenames:
    basename, extension = os.path.splitext(filename)
    if extension == db_file_extension:
      if verbose>1: print("  Adding file '%s'..." % (basename))
      parts = string.split(basename, "_")
      ctype = parts[2]
      shotid = int(parts[1])
      userid = ctype + '_%d' % int(parts[0])
      if parts[2] == "skilled" and shotid <= 40:
        sessionid = 1
      elif parts[2] == "skilled" and shotid > 40:
        sessionid = 2
      elif parts[2] == "genuine" and shotid <= 15:
        sessionid = 1
      elif parts[2] == "genuine" and shotid > 15:
        sessionid = 2
      add_file(session, basename, userid, shotid, sessionid)


def add_protocols(session, verbose):
  """Adds protocols"""

  # 1. DEFINITIONS
  enroll_shots = range(1,6)
  client_probe_shots = range(6,31)
  skilled_impostor_probe_shots = range(31,51)
  random_impostor_probe_shots = [1]
  protocols = ['skilledImpostors', 'randomImpostors']

  # 2. ADDITIONS TO THE SQL DATABASE
  protocolPurpose_list = [('eval', 'enrol'), ('eval', 'probe')]
  for proto in protocols:
    p = Protocol(proto)
    # Add protocol
    if verbose: print("Adding protocol %s..." % (proto))
    session.add(p)
    session.flush()
    session.refresh(p)
    if verbose: print("Adding protocol %s..." % (proto))
    
    # Add protocol purposes
    for key in range(len(protocolPurpose_list)):
      purpose = protocolPurpose_list[key]
      print p.id, purpose[0], purpose[1]
      pu = ProtocolPurpose(p.id, purpose[0], purpose[1])
      if verbose>1: print("  Adding protocol purpose ('%s','%s')..." % (purpose[0], purpose[1]))
      session.add(pu)
      session.flush()
      session.refresh(pu)

      # Add files attached with this protocol purpose
      if(key == 0): #test enrol
        q = session.query(File).join(Client).filter(and_(Client.sgroup == 'clientEval', Client.stype == 'genuine')).filter(File.shot_id.in_(enroll_shots))
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)

      elif(key == 1): #test probe
        q = session.query(File).join(Client).filter(and_(Client.sgroup == 'clientEval', Client.stype == 'genuine')).filter(File.shot_id.in_(client_probe_shots))
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)
        if(proto == 'skilledImpostors'): 
          q = session.query(File).join(Client).filter(and_(Client.sgroup == 'clientEval', Client.stype == 'skilled')).filter(File.shot_id.in_(skilled_impostor_probe_shots))
          for k in q:
            if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
            pu.files.append(k)
        elif(proto == 'randomImpostors'):
          q = session.query(File).join(Client).filter(and_(Client.sgroup == 'impostorEval', Client.stype == 'genuine')).filter(File.shot_id.in_(random_impostor_probe_shots))
          for k in q:
            if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
            pu.files.append(k)


def create_tables(args):
  """Creates all necessary tables (only to be used at the first time)"""

  from bob.db.utils import create_engine_try_nolock
  engine = create_engine_try_nolock(args.type, args.files[0], echo=(args.verbose > 2))
  Base.metadata.create_all(engine)

# Driver API
# ==========

def create(args):
  """Creates or re-creates this database"""

  from bob.db.utils import session_try_nolock

  dbfile = args.files[0]

  if args.recreate:
    if args.verbose and os.path.exists(dbfile):
      print('unlinking %s...' % dbfile)
    if os.path.exists(dbfile): os.unlink(dbfile)

  if not os.path.exists(os.path.dirname(dbfile)):
    os.makedirs(os.path.dirname(dbfile))

  # the real work...
  create_tables(args)
  s = session_try_nolock(args.type, dbfile, echo=(args.verbose > 2))
  add_clients(s, args.verbose)
  add_files(s, args.imagedir, args.verbose)
  add_protocols(s, args.verbose)
  s.commit()
  s.close()

def add_command(subparsers):
  """Add specific subcommands that the action "create" can use"""

  parser = subparsers.add_parser('create', help=create.__doc__)

  parser.add_argument('-R', '--recreate', action='store_true', help="If set, I'll first erase the current database")
  parser.add_argument('-v', '--verbose', action='count', help="Do SQL operations in a verbose way?")
  parser.add_argument('-D', '--imagedir', metavar='DIR', default='/home/bob/BioSecure_DS2_Sign_GlobalFeats', help="Change the relative path to the directory containing the images of the Biosecure DS2 Global Features database.")

  parser.set_defaults(func=create) #action

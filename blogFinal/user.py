#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from google.appengine.ext import ndb

from app_utils import Ut

# Block to hash user information

def users_key(group = 'default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    #def __init__(self, *a, **kw):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        #print("User.by_id: "+str(uid))
        u = cls.get_by_id(int(uid),parent=users_key())
        return u

    @classmethod
    def by_name(cls, name):
        u = User.query(User.name == name).fetch()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        u = cls.by_name(name)
        if not u:
            ut = Ut()
            pw_hash = ut.make_pw_hash(name, pw)
            return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
        else:
            return False

    @classmethod
    def login(cls, name, pw):
        ut = Ut();
        u = cls.by_name(name)
        if u and ut.valid_pw(name, pw, u.pw_hash):
            return u

#END Block to hash user information
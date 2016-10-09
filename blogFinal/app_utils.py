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
import random
import hashlib
import hmac
from string import letters
import re

class Ut():
    def __init__(self, *a, **kw):
        self.secret = "carrotsouffle"
        self.USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        self.PASS_RE = re.compile(r"^.{3,20}$")
        self.EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

    def make_secure_val(self,val):
        return '%s|%s' % (val, hmac.new(self.secret, val).hexdigest())

    def check_secure_val(self,secure_val):
        val = secure_val.split('|')[0]
        if secure_val == self.make_secure_val(val):
            return val

    # Block to hash user information
    def make_salt(self,length = 5):
        return ''.join(random.choice(letters) for x in xrange(length))

    def make_pw_hash(self,name, pw, salt = None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

    def valid_pw(self,name, password, h):
        salt = h.split(',')[0]
        return h == self.make_pw_hash(name, password, salt)


    def valid_username(self,username):
        return username and self.USER_RE.match(username)


    def valid_password(self,password):
        return password and self.PASS_RE.match(password)


    def valid_email(self,email):
        return not email or self.EMAIL_RE.match(email)

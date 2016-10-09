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
import os
import webapp2
import jinja2
import random
import hashlib
import hmac
from string import letters
import re

from google.appengine.ext import db

from app_utils import Ut
from user import User

template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class TemplateHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        ut = Ut();
        cookie_val = ut.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        ut = Ut();
        cookie_val = self.request.cookies.get(name)
        return cookie_val and ut.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        #u = User()
        self.user = uid and User.by_id(int(uid))


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class MainHandler(TemplateHandler):
    def render_front(self):
        posts = db.GqlQuery("select * from Post "
                            "order by created DESC")

        self.render("index.html",posts=posts)
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        #textarea = self.request.get("text")
        self.render_front()
        #self.response.out.write(form)

class PostPage(TemplateHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class SignupHandler(TemplateHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("signup.html")
        #self.response.out.write(form)
    def post(self):

        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)
        ut = Ut();
        if not ut.valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not ut.valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not ut.valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(SignupHandler):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class NewPostHandler(TemplateHandler):
    def render_newpost(self, subject="",content="",error=""):
        #arts = db.GqlQuery("select * from Blog "
        #                    "order by created DESC")
        self.render("newpost.html",subject=subject,content=content,error=error)
    def get(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        error = self.request.get("error")
        #self.response.headers['Content-Type'] = 'text/plain'
        #textarea = self.request.get("text")
        if subject or content or error:
            self.render_newpost(subject=subject,content=content,error=error)
        else:
            self.render("newpost.html")
        #self.response.out.write(form)
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if content and subject:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            #b.get_by_id()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "we need both a subject and content"
            self.render_newpost(subject,content,error)


class WelcomeHandler(TemplateHandler):
    def get(self):
        username=self.request.cookies.get("user_id_w")
        self.render("welcome.html",username=username)

class LoginHandler(TemplateHandler):
    def get(self):
        user_id_l=self.request.cookies.get("user_id_l")
        self.render("login.html",username=user_id_l)
    def post(self):
        # user_id_l=self.request.cookies.get("user_id_l")
        # pass_c=self.request.cookies.get("pass")
        user = self.request.get("username")
        pwd = self.request.get("password")
        u = User.login(user,pwd)

        if u:
            self.login(u)
            self.redirect("/")
        else:
            msg = "Invalid login"
            self.render("login.html",error=msg)

class LogoutHandler(TemplateHandler):
    def get(self):
        self.logout()
        self.redirect("/")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup',Register),
    ('/welcome',WelcomeHandler),
    ('/login',LoginHandler),
    ('/logout',LogoutHandler),
    ('/newpost',NewPostHandler),
    ('/blog/([0-9]+)', PostPage)
], debug=True)
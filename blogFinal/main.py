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
import re

template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

class TemplateHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
class MainHandler(TemplateHandler):

class SignupHandler(TemplateHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("signup.html")
        #self.response.out.write(form)
    def post(self):
        user = self.request.get("username")
        pwd = self.request.get("password")
        c_pass = self.request.get("verify")
        email = self.request.get("email")
        userWarning = passWarning = c_passWarning = ""

        if not user:
            userWarning = "Empty username"
        if not pwd:
            passWarning = "Empty password"
        if not c_pass:
            c_passWarning = "Confirm password"
        elif pwd != c_pass:
            passWarning = "Password do not match"


        if not re.match(r"[^@]+@[^@]+\.[^@]+",email):
            emailWarning = "Invalid email"

        if userWarning or passWarning or c_passWarning:
            self.render("signup.html",user=user,email=email,userWarning=userWarning,passWarning=passWarning,c_passWarning=c_passWarning)
        else:
            userCookie = ("user_id_w=%s; Path=/welcome" % user).encode('ascii','ignore')
            self.response.headers.add_header("Set-Cookie", userCookie)
            userCookie = ("user_id_l=%s; Path=/login" % user).encode('ascii','ignore')
            self.response.headers.add_header("Set-Cookie", userCookie)
            userCookie = ("pass=%s; Path=/login" % pwd).encode('ascii','ignore')
            self.response.headers.add_header("Set-Cookie", userCookie)

            self.redirect("/login")
        #self.redirect("/rot13")
class NewPostHandler(TemplateHandler):


class WelcomeHandler(TemplateHandler):
    def get(self):
        username=self.request.cookies.get("user_id_w")
        self.render("welcome.html",username=username)

class LoginHandler(TemplateHandler):
    def get(self):
        user_id_l=self.request.cookies.get("user_id_l")
        self.render("login.html",username=user_id_l)
    def post(self):
        user_id_l=self.request.cookies.get("user_id_l")
        pass_c=self.request.cookies.get("pass")
        user = self.request.get("username")
        pwd = self.request.get("password")
        if not user:
            userWarning = "Empty username"
        if not pwd:
            passWarning = "Empty password"
        if user and pwd:
            if user == user_id_l and pwd == pass_c:
                userCookie = ("user_id_w=%s; Path=/welcome" % user).encode('ascii','ignore')
                self.response.headers.add_header("Set-Cookie", userCookie)
                self.redirect("/welcome")
class LogoutHandler(TemplateHandler):
    def get(self):
        userCookie = ("user_id_w=%s; Path=/welcome" % None).encode('ascii','ignore')
        self.response.headers.add_header("Set-Cookie", userCookie)
        userCookie = ("user_id_l=%s; Path=/login" % None).encode('ascii','ignore')
        self.response.headers.add_header("Set-Cookie", userCookie)
        self.redirect("/signup")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup',SignupHandler),
    ('/welcome',WelcomeHandler),
    ('/login',LoginHandler),
    ('/logout',LogoutHandler)
], debug=True)
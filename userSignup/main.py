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

form = """
    <h1>Enter some text to ROT13:</h1>
    <form method="post" action="/rot13">
        <textarea style="height: 100px; width: 400px;" name="text"></textarea>
        <input type="submit">
    </form>
"""
class TemplateHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(TemplateHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("index.html")
        #self.response.out.write(form)
    def post(self):
        user = self.request.get("user")
        pass = self.request.get("pass")
        c_pass = self.request.get("c_pass")
        email = self.request.get("email")

        if not user:
            userWarning = "Empty username"
        if not pass:
            passWarning = "Empty password"
        if not c_pass:
            c_passWarning = "Confirm password"
        elif pass != c_pass:
            passWarning = "Password do not match"


        if not re.match(r"[^@]+@[^@]+\.[^@]+",email):
            emailWarning = "Invalid email"

        if userWarning or passWarning or c_passWarning or emailWarning
            self.render("index.html",user=user)
        #self.redirect("/rot13")



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/register',MainHandler)
], debug=True)
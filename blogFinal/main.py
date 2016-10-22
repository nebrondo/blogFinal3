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

#from google.appengine.ext import db
from google.appengine.ext import ndb

from app_utils import Ut
from user import User
import time

template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class SessionHandler(webapp2.RequestHandler):
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
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def check_session(self):
        user = self.read_secure_cookie("user_id")
        if user:
            return True
        else:
            return False

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        # uid = self.read_secure_cookie('user_id')
        # #u = User()
        # self.user = uid and User.by_id(int(uid))

class TemplateHandler(SessionHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    user = ndb.TextProperty(required = False)
    likes = ndb.IntegerProperty(required = False)
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    #def add(self):

class Comment(ndb.Model):
    post = ndb.KeyProperty()
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    user = ndb.TextProperty(required = False)
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)
    #def add(self):

class MainHandler(TemplateHandler):
    def render_front(self,error=""):
        q = Post.query()
        #q = q.order(Post.created)

        posts = q.fetch(50)
        if not posts:
            posts = Empty
        print("cm: %s" % type(super).__name__)
        self.render("index.html",posts=posts,loggedIn=self.check_session(),error=error)
    def get(self,error=""):
        #self.response.headers['Content-Type'] = 'text/plain'
        #textarea = self.request.get("text")
        self.render_front(error)
        #self.response.out.write(form)

class SignupHandler(TemplateHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("signup.html",params=None,loggedIn=self.check_session())
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
            params['userWarning'] = "That's not a valid username."
            have_error = True

        if not ut.valid_password(self.password):
            params['passWarning'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['c_passWarning'] = "Your passwords didn't match."
            have_error = True

        if not ut.valid_email(self.email):
            params['emailWarning'] = "That's not a valid email."
            have_error = True
        if not have_error:
            u = User.by_name(self.username)
            if u:
                params['duplicateWarning'] = 'That user already exists.'
                have_error=True
            else:
                u = User.register(self.username, self.password, self.email)
                if u != False:
                    u.put()
                    self.login(u)
                    self.redirect('/')
                else:
                    params['notFoundWarning']='User account not found'
                    have_error=True
        if have_error:
            self.render('signup.html',params=params,loggedIn=self.check_session())

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(SignupHandler):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg,loggedIn=self.check_session())
        else:
            u = User.register(self.username, self.password, self.email)
            if u != False:
                u.put()
                self.login(u)
                self.redirect('/')
            else:
                self.params['error_duplicate']
                self.render('signup.html',params,loggedIn=self.check_session())

class NewPostHandler(TemplateHandler):
    def render_newpost(self, subject="",content="",error=""):
        #arts = db.GqlQuery("select * from Blog "
        #                    "order by created DESC")
        self.render("newpost.html",subject=subject,content=content,error=error,loggedIn=self.check_session())
    def get(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        user = self.read_secure_cookie("user_id")
        if user:
            error = self.request.get("error")
            #self.response.headers['Content-Type'] = 'text/plain'
            #textarea = self.request.get("text")
            if subject or content or error:
                self.render_newpost(subject=subject,content=content,error=error)
            else:
                self.render("newpost.html",loggedIn=self.check_session())
        else:
            self.redirect("/login")
        #self.response.out.write(form)
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        user = self.read_secure_cookie("user_id")
        if user:
            us = User()
            u=us.by_id(int(user))

            if content and subject and u:
                p = Post(parent = blog_key(), subject = subject, content = content,likes=0,user=u.name)
                p.put()
                #b.get_by_id()
                self.redirect('/blog/%s' % str(p.key.id()))
            else:
                error = "we need both a subject and content"
                self.render_newpost(subject,content,error)
        else:
            self.redirect("/login")

    # ('/editpost',EditPostHandler),

def check_sess():
    sess = SessionHandler()
    return sess.check_session()
class PostPage(TemplateHandler):

    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        print("PostPage: "+post_id)
        q=Comment.query(Comment.post==post.key)
        # q.filter("post=",int(post_id))
        # print(q)
        comments = q.fetch(5)
        # print(comments)
        # comments = Comment.query(Comment.post == key).fetch()
        # print(comments)
        # DO NOT UNCOMMENT
        # comments.order("-created")
        # for c in comments:
        #     print(c.content)

        print("cm: %s" % issubclass(PostPage, Comment))
        user=self.read_secure_cookie("user_id")
        loggedIn=False
        if user:
            loggedIn= True

        self.render("permalink.html", post=post,comments=comments,loggedIn=self.check_session())

class EditPostHandler(TemplateHandler):
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        user = self.read_secure_cookie("user_id")
        if user:
            print("User is: %s" % user)
            us=User()
            print("Type of us is: %s" % type(us))
            u=us.by_id(int(user))
            print("Type of u is: %s" % type(u))
            # print("EditPostHandler: "+ us)
            if post.user == u.name:
                #b.get_by_id()
                self.render("editpost.html", post = post,loggedIn=self.check_session())
            elif post.user != u.name:
                self.response.write("You can't Edit other people's posts!!")
        else:
            self.redirect("/login")
    def post(self,post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if content and subject:
            post.subject = subject
            post.content = content
            post.put()
            #b.get_by_id()
            self.redirect('/blog/%s' % str(post.key.id()))
        else:
            error = "we need both a subject and content"
            self.render("editpost.html",post=post,error=error)
    # ('/deletepost',DeletePostHandler),
class DeletePostHandler(TemplateHandler):
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        #posts = Post.all(keys_only=True)
        post = key.get()
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(int(user))

            if post and post.user == u.name:
                #db.delete(posts) #Use in case of emergency ONLY to erase all records
                post.key.delete()
                time.sleep(0.1)
                self.redirect('/')
            elif post.user != u.name:
                self.response.write("You can't delete other people's posts!!")
        else:
            self.redirect("/login")
    # ('/likepost',LikePostHandler),
class LikePostHandler(TemplateHandler):
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(user)

        if not user:
            self.redirect("/login")
        elif post and post.user != u.name:
            if post.likes:
                post.likes += 1
            else:
                post.likes = 1
            post.put()
            self.redirect('/blog/%s' % post_id)
        elif post.user == u.name:
            self.response.write("You can't like you own posts!!")
    # ('/commentpost',CommentPostHandler),


class NewCommentHandler(TemplateHandler):
    def render_newpost(self, subject="",content="",error=""):
        #arts = db.GqlQuery("select * from Blog "
        #                    "order by created DESC")
        self.render("newpost.html",subject=subject,content=content,error=error,loggedIn=self.check_session())
    def post(self,post_id):
        content = self.request.get("comment")
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(int(user))
            if content:
                key = ndb.Key('Post', int(post_id), parent=blog_key())
                c = Comment(post = key, content = content,user=u.name)
                c.put()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(post_id))
            else:
                error = "Please add content into the comment field!!!"
                self.response.write(error)
        else:
            self.redirect("/login")


class CommentPostHandler(TemplateHandler):
    def get(self,post_id):
        print("blablo")
    def post(self,post_id):
        content = self.request.get("comment")
        user = self.read_secure_cookie("user_id")
        u=User.by_id(int(user))
        print("CommentPostHandler: "+u.name)
        if content:
            print("CommentPostHandler: "+content)
            print("CommentPostHandler: "+post_id)
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            c = Comment(post = key, content = content,user=u.name)
            c.put()
            #b.get_by_id()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "Please add content into the comment field!!!"
            self.response.write(error)
class EditCommentHandler(TemplateHandler):
    def get(self,comment_id):
        # key = ndb.Key('Post', int(post_id), parent=blog_key())
        # post = key.get()
        # print("EditComment Post ID: %s" % post_id)
        # if not post:
        #     self.error(404)
        #     return
        # print("Comment: %s" % comment_id)
        c_key = ndb.Key('Comment',int(comment_id))

        comment = c_key.get()
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(int(user))
            if comment.user == u.name:
                #b.get_by_id()
                self.render("postcomment.html", c = comment,loggedIn=self.check_session())
            elif comment.user != u.name:
                self.response.write("You can't Edit other people's posts!!")
        else:
            self.redirect("/login")
    def post(self,comment_id):
        #print(post_id)
        content = self.request.get("comment")
        user = self.read_secure_cookie("user_id")
        u=User.by_id(int(user))

        if content:
            key = ndb.Key('Comment', int(comment_id))
            c = key.get()
            c.content = content
            c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(c.post.id()))
        else:
            error = "we need both a subject and content"
            self.render_newpost(subject,content,error)
    # ('/deletepost',DeletePostHandler),
class DeleteCommentHandler(TemplateHandler):
    def get(self,comment_id):
        key = ndb.Key('Comment', int(comment_id))
        #posts = Post.all(keys_only=True)
        c = key.get()
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(int(user))

            if c and c.user == u.name:
                #db.delete(posts) #Use in case of emergency ONLY to erase all records
                c.key.delete()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(c.post.id()))
            elif c.user != u.name:
                self.response.write("You can't delete other people's posts!!")
        else:
            self.redirect("/login")

    # ('/likepost',LikePostHandler),
class WelcomeHandler(TemplateHandler):
    def get(self):
        username=self.request.cookies.get("user_id_w")
        self.render("welcome.html",username=username,loggedIn=self.check_session())

class LoginHandler(TemplateHandler):
    def get(self,error=""):
        user=self.request.cookies.get("user_id")
        if not user and error:
            self.render("login.html",error=error)
        else:
            self.render("login.html",username=user,loggedIn=self.check_session(),error=error)
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
            self.render("login.html",error=msg,loggedIn=self.check_session())

class LogoutHandler(TemplateHandler):
    def get(self):
        self.logout()
        self.redirect("/login")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/([0-9]+)', PostPage),
    ('/signup',SignupHandler),
    ('/login',LoginHandler),
    ('/welcome',WelcomeHandler),
    ('/newpost',NewPostHandler),
    ('/editpost/([0-9]+)',EditPostHandler),
    ('/delete/([0-9]+)',DeletePostHandler),
    ('/newcomment/([0-9]+)',NewCommentHandler),
    ('/editcomment/([0-9]+)',EditCommentHandler),
    ('/deletecomment/([0-9]+)',DeleteCommentHandler),
    ('/like/([0-9]+)',LikePostHandler),
    ('/postwcomment/([0-9]+)',CommentPostHandler),
    ('/logout',LogoutHandler)
], debug=True)
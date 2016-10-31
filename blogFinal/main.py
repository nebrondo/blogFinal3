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
import time

from google.appengine.ext import ndb
from app_utils import Ut
from user import User

config = {'error':''}
template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class SessionHandler(webapp2.RequestHandler):
    """Class that handles seesion info across the module.

    The class will hold methods to deal with session cookies as well as
    checking for the session status, initialize the cookie (login) and
    finilize the cookie (logout)
    """
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
            us = User()
            u=us.by_id(int(user))
            return u.name
        else:
            return False
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

class TemplateHandler(SessionHandler):
    """Class dealing with template rendering. Inherits SessionHandler"""
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
    """ Class that creates the Post model.
    Attributes:
        subject: will hold the subject of the blog post
        content: will hold the content of the blog post
        last_modified: last modified date
        user: will hold the owner of the post
        likes: will hold the count of total likes for the post
    Methods:
        render: will render a blog post with required paramenters
    """
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    user = ndb.TextProperty(required = False)
    likes = ndb.IntegerProperty(required = False)
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(ndb.Model):
    """ Class that creates a model for a Comment on a post
    Attributes:
        post: holds a key to the parent post
        content: will hold the content of the comment
        last_modified: last modified date
        user: will hold the owner of the comment
    Methods:
        render: will render the comment page with required paramenters
    """
    post = ndb.KeyProperty()
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    user = ndb.TextProperty(required = False)
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

class Like(ndb.Model):
    post = ndb.KeyProperty()
    user = ndb.TextProperty(required = True,indexed = True)

class MainHandler(TemplateHandler):
    """Class that handles the landing page, displaying a list of blog posts

    Methods:
        render_front: queries for existing posts and sends it to index.html template
    """
    def render_front(self,error=""):
        q = Post.query()
        posts = q.fetch(50)
        if not posts:
            posts = []
        self.render("index.html",posts=posts,loggedIn=self.check_session(),error=error)
    def get(self,error=""):
        self.render_front(error)

class SignupHandler(TemplateHandler):
    """Class that handles user signup

    Methods:
        get: renders the signup template with the check for the session cookie
        post: will collect user information from the request object and will
              store that into the User model. It will validate for valid data
              and will send error messages if the values are empty or invalid
    """
    def get(self):
        self.render("signup.html",params=None,loggedIn=self.check_session())
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

class NewPostHandler(TemplateHandler):
    """Class that handles new posts

    Methods:
        get: will grab subject and content in case there was an error in order
             to fix the error and having the previous entered values available
        post: will collect user information from the request object and will
              store that into the User model. It will validate for valid data
              and will send error messages if the values are empty or invalid
    """
    def render_newpost(self, subject="",content="",error=""):
        if not subject:
            self.render("newpost.html",loggedIn=self.check_session())
        else:
            self.render("newpost.html",subject=subject,content=content,error=error,loggedIn=self.check_session())
    def get(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        user = self.read_secure_cookie("user_id")
        if user:
            error = self.request.get("error")
            if subject and content:
                self.render_newpost(subject=subject,content=content,error=error)
            else:
                self.render_newpost()
        else:
            self.redirect("/login")
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
                self.redirect('/blog/%s' % str(p.key.id()))
            elif not u:
                error = "Invalid user, please login/register and try again"
                self.logout()
                self.redirect("/login")
            else:
                error = "we need both a subject and content"
                self.render_newpost(subject,content,error)
        else:
            self.redirect("/login")

class PostPage(TemplateHandler):
    """Class that handles the post pages as individual links by post ID

    Methods:
        get: method that will find the post by ID as well as comments
    """
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        q=Comment.query(Comment.post==post.key)
        comments = q.fetch(5)
        user=self.read_secure_cookie("user_id")
        loggedIn=False
        if user:
            loggedIn= True
        self.render("permalink.html", post=post,comments=comments,loggedIn=self.check_session())

class EditPostHandler(TemplateHandler):
    """Class that handles post edition by user id

    Methods:
        get: This method will handle the edit post permissions by user id
        post: If a user is validated as owner of a post will grab the info and
              post into the datastore
    """
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        user = self.read_secure_cookie("user_id")
        if user:
            us=User()
            u=us.by_id(int(user))
            if post.user == u.name:
                self.render("editpost.html", post = post,loggedIn=self.check_session())
            elif post.user != u.name:
                self.response.write("You can't Edit other people's posts!!")
        else:
            self.redirect("/login")
    def post(self,post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")

        user = self.read_secure_cookie("user_id")
        if user:
            us = User()
            u=us.by_id(int(user))

            if content and subject and u:

                key = ndb.Key('Post', int(post_id), parent=blog_key())
                post = key.get()
                if post.user == u.name:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key.id()))
                else:
                    self.response.write("You can't Edit other people's posts!!")
            elif not u:
                error = "Invalid user, please login/register and try again"
                self.logout()
                self.redirect("/login")
            else:
                error = "we need both a subject and content"
                self.render("editpost.html",post=post,error=error)

class DeletePostHandler(TemplateHandler):
    """Class takes care of deleting a post for logged in user

    Methods:
        get: the method will validate user ownership and will delete the post
             and rederect to the post list page
    """
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
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

class LikePostHandler(TemplateHandler):
    """Class handling one like per user, preventing liking own posts

    Methods:
        get: like a post for a particular post id, validate the current user
             in order to prevent liking own posts. It will only allow for one
             like per user.
    """
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(user)
            if post and post.user != u.name:
                likes = len(Like.query(Like.post==post.key,Like.user==user).fetch())
                if likes == 0:
                    l = Like(post=post.key,user=user)
                    l.put()
                    post.likes += 1
                    post.put()
                    self.redirect('/blog/%s' % post_id)
            elif post.user == u.name:
                self.response.write("You can't like you own posts!!")
        else:
            self.redirect("/login")


class NewCommentHandler(TemplateHandler):
    """Class takes care of new comments on an existing post

    Methods:
        post: will send comment into the datastore and associate it to a post
              as parent model. It will then redirect back to the post page
    """
    def render_newpost(self, subject="",content="",error=""):
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

class EditCommentHandler(TemplateHandler):
    """Class to enable editting comments to the its owner

    Methods:
        get: will handle the validation of ownership in order to load the edit
             page
        post: method to handle the posting into the datastore associating it
              with the post and the user. When done it will redirect to the
              associated post page.
    """
    def get(self,comment_id):
        c_key = ndb.Key('Comment',int(comment_id))
        comment = c_key.get()
        user = self.read_secure_cookie("user_id")
        if user and comment:
            u=User.by_id(int(user))
            if comment.user == u.name:
                self.render("postcomment.html", c = comment,loggedIn=self.check_session())
            elif comment.user != u.name:
                self.response.write("You can't Edit other people's posts!!")
        elif not comment:
            self.response.write("Could not retrieve comment")
        else:
            self.redirect("/login")
    def post(self,comment_id):
        content = self.request.get("comment")
        user = self.read_secure_cookie("user_id")
        u=User.by_id(int(user))
        if content:
            key = ndb.Key('Comment', int(comment_id))
            c = key.get()
            if comment and c.user == u.name:
                c.content = content
                c.put()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(c.post.id()))
            else:
                self.response.write("Could not retrieve comment")
        else:
            error = "we need both a subject and content"
            self.render_newpost(subject,content,error)

class DeleteCommentHandler(TemplateHandler):
    """Class takes care of deleting a comment for its owner only

    Methods:
        get: validates current user and proceeds with deleteing if it matches
             the user logged in.
    """
    def get(self,comment_id):
        key = ndb.Key('Comment', int(comment_id))
        c = key.get()
        user = self.read_secure_cookie("user_id")
        if user:
            u=User.by_id(int(user))
            if c and c.user == u.name:
                c.key.delete()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(c.post.id()))
            elif c.user != u.name:
                self.response.write("You can't delete other people's posts!!")
        else:
            self.redirect("/login")

class WelcomeHandler(TemplateHandler):
    def get(self):
        username=self.request.cookies.get("user_id_w")
        self.render("welcome.html",username=username,loggedIn=self.check_session())

class LoginHandler(TemplateHandler):
    """Class dealing with starting a user session

    Methods:
        get:  loads the login page and validates if the user is not logged in
              already
        post: validates the user in the datastore and redirects to the main
              page
    """
    def get(self,error=""):
        user=self.request.cookies.get("user_id")
        if not user:
            self.render("login.html",error=error)
        else:
            self.render("login.html",username=user,loggedIn=self.check_session(),error=error)
    def post(self):
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
    ('/logout',LogoutHandler)
], config=config,debug=True)
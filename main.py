from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUserForm, CreateLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("APP_SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# SETUP Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def create_hash_gravatar(email):
    return hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest()

# Setup LoginManager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


# Admin Only Decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    # Parent for Blogpost
    posts = relationship("BlogPost", back_populates="author")

    # Parent for Comments
    comments = relationship("Comment", back_populates="comment_author")

    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Child for Users
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("Users", back_populates="posts")

    # Parent for Comment
    comments = relationship("Comment", back_populates="parent_post")

    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Child for Users
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("Users", back_populates="comments")

    # Child for BlogPost
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.String(250), nullable=False)


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    # Wenn Submit Button gedrückt wurde
    if form.validate_on_submit():
        # Gucken ob E-Mail schon in der Datenbank hinterlegt ist
        exists = Users.query.filter_by(email=form.email.data).first() is not None
        if exists:
            flash("You've already signed up with that email, log in instead!")
            return redirect("login")
        hashed_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = Users(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = CreateLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # User Account in der Datenbank finden
        user_account = Users.query.filter_by(email=email).first()
        # Checken, ob E-Mail in der Datenbank vorhanden ist
        if user_account:
            # Checken, ob Passwort mit dem in der Datenbank übereinstimmt
            if check_password_hash(user_account.password, password):
                # Log user in
                login_user(user_account)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password incorrect. Please try again.")
                return redirect("login")
        # User existiert nicht und dieser Email
        else:
            flash("That email does not exist. Please try again.")
            return redirect("login")

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CreateCommentForm()

    # Wenn Submit gedrückt wird, wird das Kommentar in der Datenbank abgespeichert
    if form.validate_on_submit():
        # Check if user is logged in
        if current_user.is_authenticated:
            new_comment = Comment(
                author_id=current_user.id,
                post_id=post_id,
                text=form.body.data,
            )
            db.session.add(new_comment)
            db.session.commit()
        # If User is not logged in he gets a flash message, and he will be returned to login
        else:
            flash("Please login first.")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

# TODO beim EDIT von einem Beitrag wird der Autor auf den current user gesetzt und kein Autor mehr angezeigt
#  in der Übersicht

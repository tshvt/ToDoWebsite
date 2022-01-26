from flask import Flask, render_template, redirect, url_for, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from datetime import date
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from sqlalchemy.sql.expression import func
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)

Bootstrap(app)
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# FORMS
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up")


class LogInForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class NewPlan(FlaskForm):
    title = StringField("What you're planning to do?", validators=[DataRequired()])
    submit = SubmitField("Add")


# TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    user_plans = relationship("Plan", back_populates="author")
    user_dones = relationship("Done", back_populates="author")


class Plan(db.Model):
    __tablename__ = "plans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="user_plans")
    title = db.Column(db.String(250), unique=True, nullable=False)
    date = db.Column(db.String(250), nullable=False)


class Done(db.Model):
    __tablename__ = "dones"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="user_dones")
    title = db.Column(db.String(250), unique=True, nullable=False)
    date = db.Column(db.String(250), nullable=False)


# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ROUTES
@app.route("/", methods=["GET", "POST"])
def home():
    login_form = LogInForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user:
            if check_password_hash(user.password, login_form.password.data):
                login_user(user)
                return redirect(url_for("show_decks", user_id=current_user.id))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for('home'))
        else:
            flash("That email does not exist. Please try again!")
            return redirect(url_for('home'))
    return render_template("index.html", form=login_form)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("You've already signed up with this email. Log In instead!")
            return redirect(url_for('home'))
        else:
            hash_password = generate_password_hash(
                password=register_form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                email=register_form.email.data,
                password=hash_password,
                name=register_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("show_decks", user_id=current_user.id))
    return render_template("register.html", form=register_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/decks/<int:user_id>", methods=["GET", "POST"])
@login_required
def show_decks(user_id):
    user_plans = Plan.query.filter_by(user_id=user_id).all()
    user_dones = Done.query.filter_by(user_id=user_id).all()
    new_plan_form = NewPlan()
    if new_plan_form.validate_on_submit():
        new_plan = Plan(
            user_id=current_user.id,
            title=new_plan_form.title.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_plan)
        db.session.commit()
        return redirect(url_for('show_decks', user_id=current_user.id))
    return render_template("deck.html", plans=user_plans, dones=user_dones, form=new_plan_form)


@app.route("/delete/<int:plan_id>")
@login_required
def delete_plan(plan_id):
    plan_delete = Plan.query.get(plan_id)
    db.session.delete(plan_delete)
    db.session.commit()
    return redirect(url_for('show_decks', user_id=current_user.id))


@app.route("/done/<int:plan_id>")
@login_required
def done_plan(plan_id):
    plan_to_done = Plan.query.get(plan_id)
    new_done = Done(
        user_id=current_user.id,
        title=plan_to_done.title,
        date=date.today().strftime("%B %d, %Y")
    )
    db.session.add(new_done)
    db.session.commit()
    db.session.delete(plan_to_done)
    db.session.commit()
    return redirect(url_for('show_decks', user_id=current_user.id))


@app.route("/delete-all-plans/<int:user_id>")
@login_required
def delete_plans(user_id):
    db.session.query(Plan).filter(Plan.user_id == user_id).delete()
    db.session.commit()
    return redirect(url_for('show_decks', user_id=current_user.id))


@app.route("/delete-all-dones/<int:user_id>")
@login_required
def delete_dones(user_id):
    db.session.query(Done).filter(Done.user_id == user_id).delete()
    db.session.commit()
    return redirect(url_for('show_decks', user_id=current_user.id))


if __name__ == "__main__":
    app.run(debug=True)

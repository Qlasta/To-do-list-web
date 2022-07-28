from flask import Flask,render_template, redirect, url_for, flash, request
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FormField, FieldList
from wtforms.validators import DataRequired, Length, Email
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# App configuration

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///list.db'
app.config['SECRET_KEY'] = os.environ['APP_KEY']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ['REC_PUBLIC']
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ['REC_PRIVATE']
RECAPTCHA_PARAMETERS = {'hl': 'zh', 'render': 'explicit'}
RECAPTCHA_DATA_ATTRS = {'theme': 'dark'}
db = SQLAlchemy(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

# Databases conf

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    record = relationship("Record", back_populates="user")

    def __repr__(self):
        return '<User %r>' % self.email


class Record(db.Model):
    __tablename__ = "records"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(250))
    text = db.Column(db.String(1000), nullable=False)
    completed = db.Column(db.Boolean, nullable=False)
    user = relationship("User", back_populates="record")
    user_id = Column(Integer, ForeignKey("user.id"))



    def __repr__(self):
        return '<Record %r>' % self.id

# Forms configuration

class RegitstrationForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(), Length(4,120), Email()])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(6,80)])
    # recatcha = RecaptchaField()
    submit = SubmitField(label="Go!")


class AddRecord(FlaskForm):
    completed = BooleanField(label="")
    text = StringField()
    # text = StringField(render_kw={'style': 'width: 100ch'})
    save = SubmitField(label="Add")


class Records(FlaskForm):
    records = FieldList(FormField(AddRecord, separator="naujas"), min_entries=2)

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Index
@app.route('/', methods=["GET", "POST"])
def index():
    if current_user.is_authenticated:
        record = AddRecord()
        user_records = Record.query.filter_by(user_id=current_user.id)
        if request.method == "POST":
            new_record = Record(completed=record.completed.data, text=record.text.data, user_id=current_user.id, date=datetime.now().strftime("%Y-%m-%d, %H:%M:%S"))
            db.session.add(new_record)
            db.session.commit()
            return redirect(url_for('index'))
        return render_template("index.html",  record_form=record, logged_in=True, user_records=user_records)
    else:
        return render_template("index.html", logged_in=False)

# Register
@app.route('/register', methods=["GET", "POST"])
def register():
    register = RegitstrationForm()
    if request.method == "POST":
        if User.query.filter_by(email=register.email.data).first():
            flash("You have already registered, please log in.")
        else:
            new_user = User(email=register.email.data, password=generate_password_hash(register.password.data, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('index'))

    return render_template("register.html", register=register)

# Log in
@app.route('/login', methods=["GET", "POST"])
def login():
    login = RegitstrationForm()
    if request.method == "POST":
        if User.query.filter_by(email=login.email.data).first():
            current_user = User.query.filter_by(email=login.email.data).first()

            if check_password_hash(current_user.password, login.password.data):
                login_user(current_user)
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials.')
        else:
            flash('User does not exist, please register.')

    return render_template("login.html", login=login)


# Complete and uncomplete record

@app.route('/complete/<int:record_id>')
def mark_done(record_id):
    current_record = Record.query.get(record_id)
    if current_user.is_authenticated:
        if current_record.user_id == current_user.id:
            if current_record.completed == False:
                current_record.completed = 1
                db.session.commit()
            elif current_record.completed == True:
                current_record.completed = 0
                db.session.commit()
            return redirect(url_for('index'))
        else:
            flash("Access denied.")
            return redirect(url_for('index'))
    else:
        flash("Access denied.")
        return redirect(url_for('index'))

# Delete record
@app.route('/delete/<int:record_id>')
def delete_record(record_id):
    current_record = Record.query.get(record_id)
    if current_user.is_authenticated:
        if current_record.user_id == current_user.id:
            db.session.delete(current_record)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash("Access denied.")
            return redirect(url_for('index'))
    else:
        flash("Access denied.")
        return redirect(url_for('index'))

# Edit record
@app.route('/edit/<int:record_id>', methods=["GET", "POST"])
def edit_record(record_id):
    current_record = Record.query.get(record_id)
    if current_user.is_authenticated:
        if current_record.user_id == current_user.id:
            record_form = AddRecord()
            edit_form = AddRecord(text=current_record.text)
            user_records = Record.query.filter_by(user_id=current_user.id)
            if request.method == "POST":
                current_record.text = record_form.text.data
                db.session.commit()
                return redirect(url_for('index'))
            else:

                return render_template("index.html", record_form=record_form, edit_form=edit_form, logged_in=True, user_records=user_records, editable_record=record_id)
        else:
            flash("Access denied.")
    else:
        flash("Access denied.")
    return redirect(url_for('index'))

# Log out
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Debug mode
if __name__ ==  "__main__" :
    app.run(debug=True)
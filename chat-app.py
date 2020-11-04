from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from passlib.hash import pbkdf2_sha256
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from flask_socketio import SocketIO, send
from flask_login import UserMixin
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]=os.environ.get("DATABASE_URL")
app.secret_key = os.environ.get("secret")
db = SQLAlchemy(app)


#socket intialise
socketio = SocketIO(app, manage_session=False)

# Predefined rooms for chat
ROOMS = ["Coding", "Apk-Crack", "Games", "Pron"]

#configure flask_login
login = LoginManager(app)
login.init_app(app)

#flask_login iniitalisation
@login.user_loader
def load_user(id):
	return User.query.filter_by(id=id).first()


def invalid_credentials(form, field):
	"""username and password checker"""
	username = form.username.data
	password = field.data
	"""check credentials are valid"""
	user_data = User.query.filter_by(username=username).first()
	if user_data is None:
		raise ValidationError("Username or Password is incorrect")
	elif not pbkdf2_sha256.verify(password, user_data.password):
		raise ValidationError("Username or Password is incorrect")
	


# connect the tables with databse table
class User(UserMixin, db.Model):
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(12), unique=True, nullable=False)
	password = db.Column(db.String(), nullable=False)
	
#Registration Form using WTF	
class registration(FlaskForm):
	username = StringField("username", validators=[InputRequired(message="please enter username"), Length(min=4, max=12, message="Username must be 8 to 12 characters")])
	password = PasswordField("password", validators=[InputRequired(message="Please Enter Password"), Length(min=8, max=12, message="Password must be 8 to 12 characters")])
	confirm = PasswordField("confirm_psd", validators=[InputRequired(message="Please Confirm password "), EqualTo("password", message="password must match")])
	submit = SubmitField("create")

#custom validators for username check	
def validate_username(self, username):
	user_object = User.query.filter_by(username=username.data).first()
	if user_object:
		raise ValidationError("Someone! Already Taken that Username")	

				
# Login form using WTF
class Login(FlaskForm):
		username = StringField("username",validators=[InputRequired(message="Please Enter Username")])
		password = PasswordField("password", validators =[InputRequired(message = "Please Enter Password"), invalid_credentials])
		submit = SubmitField("Login")	

#message bucket for socketio
@socketio.on('incoming-msg')
def on_message(data):
    """Broadcast messages"""

    msg = data["msg"]
    username = data["username"]
    room = data["room"]
    # Set timestamp
    time_stamp = time.strftime('%b-%d %I:%M%p', time.localtime())
    send({"username": username, "msg": msg, "time_stamp": time_stamp}, room=room)


@socketio.on('join')
def on_join(data):
    """User joins a room"""

    username = data["username"]
    room = data["room"]
    join_room(room)

    # Broadcast that new user has joined
    send({"msg": username + " has joined the " + room + " room."}, room=room)


@socketio.on('leave')
def on_leave(data):
    """User leaves a room"""

    username = data['username']
    room = data['room']
    leave_room(room)
    send({"msg": username + " has left the room"}, room=room)
    				
				
#registration route	
@app.route("/", methods = ["GET", "POST"])
def index():
	reg_form = registration()
	if reg_form.validate_on_submit():
		username = reg_form.username.data
		password = reg_form.password.data
		# hashed password
		enc_pass = pbkdf2_sha256.hash(password)		
		#add  the username
		user = User(username=username, password=enc_pass)
		db.session.add(user)
		db.session.commit()
		flash("Regestration successfuly. Please Login", "success")
		return redirect(url_for("login"))
						
	return render_template("index.html", reg_form = reg_form)

#Login route	
@app.route("/login", methods = ["GET", "POST"])
def login():
	login_form = Login()
	if login_form.validate_on_submit():
		user_object = User.query.filter_by(username=login_form.username.data).first()
		login_user(user_object)
		return redirect (url_for("chat"))
				
	return render_template("login.html", login_form = login_form)

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

@app.route("/chat", methods = ["GET", "POST"])
#@login.required
def chat():
		if not current_user.is_authenticated:
			flash("Please Login",  "danger")
			return redirect(url_for("login"))
		return render_template("chat.html")


@app.route("/logout", methods =["GET"])
def logout():
	logout_user()
	flash("You have logged out successfully", "success")			
	return redirect(url_for("login"))
	
if __name__ == "__main__":
	app.run()
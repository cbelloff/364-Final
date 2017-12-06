import os
from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_script import Manager, Shell
# from flask_moment import Moment # requires pip/pip3 install flask_moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand # needs: pip/pip3 install flask-migrate
from flask import jsonify

from flask import send_from_directory

from flask_mail import Mail, Message
from threading import Thread
from werkzeug import secure_filename

import requests

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Configure base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# Application configurations
app = Flask(__name__)
app.debug = True
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'hardtoguessstringfromsi364thisisnotsupersecurebutitsok'

UPLOAD_FOLDER = 'resumes/'
ALLOWED_EXTENSIONS = ["pdf"]
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# app.config['SQLALCHEMY_DATABASE_URI'] =\
	# 'sqlite:///' + os.path.join(basedir, 'data.sqlite') # Determining where your database file will be stored, and what it will be called
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/final_project" # TODO: decide what your new database name will be, and create it in postgresql, before running this new application (it's similar to an old one, but has some more to it)
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set up Glassdoor API keys
API_PARTNER_ID = "233837"
API_KEY = "cCA3O0WfKQy"

# Set up email config stuff
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587 #default
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # TODO export to your environs -- may want a new account just for this. It's expecting gmail, not umich
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SUBJECT_PREFIX'] = '[COMPANY APP]'
app.config['MAIL_SENDER'] = 'Admin <carlyb382@gmail.com>' # TODO fill in email
app.config['ADMIN'] = os.environ.get('MAIL_USERNAME')

# Set up Flask debug stuff
manager = Manager(app)
# moment = Moment(app) # For time # Later
db = SQLAlchemy(app) # For database use
migrate = Migrate(app, db) # For database use/updating
manager.add_command('db', MigrateCommand) # Add migrate command to manager
mail = Mail(app) # For email sending

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)

def send_email(to, subject, template, **kwargs): # kwargs = 'keyword arguments', this syntax means to unpack any keyword arguments into the function in the invocation...
	msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
				  sender=app.config['MAIL_SENDER'], recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	thr = Thread(target=send_async_email, args=[app, msg]) # using the async email to make sure the email sending doesn't take up all the "app energy" -- the main thread -- at once
	thr.start()
	return thr # The thread being returned
	# However, if your app sends a LOT of email, it'll be better to set up some additional "queuing" software libraries to handle it. But we don't need to do that yet. Not quite enough users!



class User(UserMixin, db.Model):
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(100), unique=True)
	password_hash = db.Column(db.String(128))

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id)) # returns User object or None

class Company(db.Model):
	__tablename__ = "companies"
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64))
	Location=db.Column(db.Integer, db.ForeignKey("locations.id"))
	reviewlink=db.Column(db.String(200))


class Location(db.Model):
	__tablename__ = "locations"
	id = db.Column(db.Integer, primary_key=True)
	state=db.Column(db.String(64))
	
class User_Company(db.Model):
	__tablename__ = "user_company"
	id = db.Column(db.Integer, primary_key=True)
	user_id=db.Column(db.Integer, db.ForeignKey("users.id"))
	company_id=db.Column(db.Integer, db.ForeignKey("companies.id"))

def get_or_create_user(email):
	user = db.session.query(User).filter_by(email=email).first()
	if user:
		return user
	else:
		user = User(email=email)
		db.session.add(user)
		db.session.commit()
		return user

def get_or_create_location(state):
	location = db.session.query(Location).filter_by(state=state).first()
	if location:
		return location
	else:
		location = Location(state=state)
		db.session.add(location)
		db.session.commit()
		return location
		
def get_or_create_company(name, location_name, reviewlink=""):
	company = db.session.query(Company).filter_by(Location=get_or_create_location(location_name).id, name = name).first()
	if company:
		return company
	else:
		company = Company(Location=get_or_create_location(location_name).id, name = name, reviewlink=reviewlink)
		db.session.add(company)
		db.session.commit()
		return company

def add_to_wishlist(name, location_name, user_id):
	wishlist_item = db.session.query(User_Company).filter_by(user_id=user_id, company_id=get_or_create_company(name, location_name).id).first()
	if wishlist_item:
		return wishlist_item
	else:
		wishlist_item = User_Company(user_id=user_id, company_id=get_or_create_company(name, location_name).id)
		db.session.add(wishlist_item)
		db.session.commit()
		return wishlist_item

# For a searchString (company name or a job title) and a given state (2 letter abbreviation), return a list of employers
def getSearchData(searchString = "", searchState = ""):
	data =  requests.get("http://api.glassdoor.com/api/api.htm?t.p={}&t.k={}&userip=0.0.0.0&useragent=&&format=json&v=1&action=employers&q={}&state={}".format(API_PARTNER_ID, API_KEY, searchString, searchState), headers = {
	'User-Agent': 'My User Agent 1.0'}).json()["response"]["employers"]
	for company in data:
		if "featuredReview" in company:
			featuredReview = company["featuredReview"]['attributionURL']
		else:
			featuredReview = ""
		get_or_create_company(company["name"], searchState, featuredReview)
	return data

## Necessary for behind the scenes login manager that comes with flask_login capabilities! Won't run without this.
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id)) # returns User object or None

##### Set up Forms #####

class JobForm(FlaskForm):
	STATE_ABBREV = ['AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA', 'HI', 'ID', 'IL', 'IN', 'IO', 'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY']

	text = StringField("Enter a company or job title that interests you", validators=[])
	location = SelectField("What state do you want to work in?", choices=[(state, state) for state in STATE_ABBREV])
	submit = SubmitField('Submit')

class RegistrationForm(FlaskForm):
	email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
	password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
	password2 = PasswordField("Confirm Password:",validators=[Required()])
	submit = SubmitField('Register User')
	
	#additional checking methods for the form
	def validate_email(self,field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')


###views###

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html')

@app.errorhandler(500)
def server_error(e):
	return render_template('500.html')

@app.route('/', methods=['GET', 'POST'])
def index():
	form = JobForm()
	return render_template('index.html', form=form)
   
@app.route('/result', methods = ['GET', 'POST'])
@login_required
def result():
	form = JobForm(request.form)
	if request.method == 'POST' and form.validate_on_submit():
		text = form.text.data
		location = form.location.data
		api_data = getSearchData(text,location)
		return render_template('results.html', companies=api_data, location=location)
	flash('All fields are required!')
	return redirect(url_for('index'))

class WishListForm(FlaskForm):
	addToWishList = SubmitField('Add to Wish List')

@app.route('/company/<company_name>/<loc>', methods = ['GET', 'POST'])
@login_required
def company_detail(company_name, loc):
	form = WishListForm()
	if request.method == 'POST' and form.validate_on_submit():
		add_to_wishlist(company_name, loc, current_user.id)
		send_email(current_user.email, 'New Company!', 'mail/new_company', name=company_name, loc=loc)
		return redirect("/")
	else:
		api_data = getSearchData(company_name,loc)[0]
		return render_template("company_detail.html", company=api_data, form=form)

# Login-related routes
@app.route('/login',methods=["GET","POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('index'))
		flash('Bad username or password.')
	return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,password=form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('You can now log in!')
		return redirect(url_for('login'))
	return render_template('register.html',form=form)


@app.route('/userlist', methods=['GET'])
@login_required
def translate():
	return jsonify({
		"wish_list" : [{"company_name" : res.Company.name, "company_state":res.Location.state} for res in db.session.query(User_Company,Company,Location).filter(User_Company.user_id==current_user.id).join(Company).join(Location)]
	})

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_resume', methods=['POST'])
@login_required
def upload_file():
	if request.method == 'POST':
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		if file.filename == '':
			flash('No selected file')
			return redirect(request.url)
		if file and allowed_file(file.filename):
			filename = secure_filename("{}.pdf".format(current_user.id))
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			return redirect(url_for('showResume', userID=current_user.id))




@app.route('/my_resume')
def showMyResume():
	return send_from_directory(app.config['UPLOAD_FOLDER'],"{}.pdf".format(current_user.id))

@app.route('/resume/<userID>')
def showResume(userID):
	return send_from_directory(app.config['UPLOAD_FOLDER'],"{}.pdf".format(userID))


if __name__ == '__main__':
	db.create_all()
	manager.run() # NEW: run with this: python main_app.py runserver
	# Also provides more tools for debugging
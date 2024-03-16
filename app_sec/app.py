# Importações
import hashlib
import requests
import re
import json, os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import random
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import SelectField, StringField, PasswordField, BooleanField, SubmitField, IntegerField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError, Email, Optional
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms.widgets import HiddenInput
from zxcvbn import zxcvbn
from detishop_cryptography import encrypt_with_hmac, generate_key, decrypt_with_hmac
from werkzeug.exceptions import RequestEntityTooLarge
from csv import writer, reader
import ast

# Configurações do aplicativo Flask
app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "catalog" 

logging.basicConfig(filename='app_detishop.log', level=logging.INFO)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 

app.config['SECRET_KEY'] = 'Tartaruga_Clastrofobica'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # Use um banco de dados real em produção
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

key = 0
hash_key = 0

#Database models
# Modelo de Usuário
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer)
    reference = db.Column(db.String(5))
    first_name = db.Column(db.String(256))
    last_name = db.Column(db.String(256))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(256))
    address = db.Column(db.String(256))
    city = db.Column(db.String(256))
    country = db.Column(db.String(256))
    status = db.Column(db.String(256))
    payment_type = db.Column(db.String(10))
    card_number = db.Column(db.String(256))
    expiration_date = db.Column(db.String(256))
    cvv = db.Column(db.String(256))
    paypal_email = db.Column(db.String(256))
    mbway_phone_number = db.Column(db.String(256))
    items = db.relationship('Order_Item', backref='order', lazy=True)

    def order_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity * Product.price)).join(Product).filter(Order_Item.order_id == self.id).scalar()
    
    def quantity_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity)).filter(Order_Item.order_id == self.id).scalar()
    
    #create print method
    def __repr__(self):
        return f"Order('{self.id}', '{self.id_user}', '{self.reference}', '{self.first_name}', '{self.last_name}', '{self.phone_number}', '{self.email}', '{self.address}', '{self.city}', '{self.country}', '{self.status}', '{self.payment_type}', '{self.items}')"
    
    #method to add order to database
    @classmethod
    def add_order(cls, id_user, reference, first_name, last_name, phone_number, email, address, city, country, status, payment_type, card_number, expiration_date, cvv, paypal_email, mbway_phone_number):
        new_order = cls(
            id_user=id_user,
            reference=reference,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            email=email,
            address=address,
            city=city,
            country=country,
            status=status,
            payment_type=payment_type,
            card_number=card_number,
            expiration_date=expiration_date,
            cvv=cvv,
            paypal_email=paypal_email,
            mbway_phone_number=mbway_phone_number
        )
        db.session.add(new_order)
        db.session.commit()
        
    #method to add product to order
    @classmethod
    def add_product(cls, order_id, product_id, quantity):
        new_order_item = Order_Item(
            order_id=order_id,
            product_id=product_id,
            quantity=quantity
        )
        db.session.add(new_order_item)
        db.session.commit()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), unique = True, nullable = False)
    password = db.Column(db.String(256), nullable = False)  # Increased length
    gender = db.Column(db.String(256), nullable = False)  # Increased length
    full_name = db.Column(db.String(256), nullable = False)  # Increased length
    email = db.Column(db.String(256), unique = True, nullable = False)
    admin = db.Column(db.Boolean, default = False)
    
    @property
    def is_admin(self):
        return self.admin
    
    @classmethod
    def add_user(cls, id_user, username, password, gender, full_name, email, admin):
        new_user = cls(
            id=id_user,
            username=username,
            password=password,
            gender=gender,
            full_name=full_name,
            email=email,
            admin=admin
        )
        db.session.add(new_user)
        db.session.commit()
        

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=12, max=128)], render_kw={"placeholder": "Password"})
    gender = SelectField('Gender', choices=(('Male'),('Female'),('Other'),('Prefer not to say')))
    email = StringField('Email', validators = [InputRequired(), Email(message = 'Invalid email'), Length(max = 50)], render_kw={"placeholder": "Email"})
    full_name = StringField('Full name', validators = [InputRequired(), Length(min = 3, max = 50)], render_kw={"placeholder": "Full name"})
    consent = BooleanField('I agree to the collection and use of my data.', validators=[InputRequired()])
    submit = SubmitField('Register')

    # CWE-20: Improper Input Validation
    def validate_username(self, username):
        existing_username = User.query.filter_by(username = username.data).first()
        if existing_username:
            raise ValidationError('Username already exists. Please choose another one.')
        
        if not re.match("^[a-zA-Z0-9]+$", username.data):
            raise ValidationError('Username can only contain alphanumeric characters.')

    def is_password_pwned(self, password):
        password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = password[:5], password[5:]

        # Make a request to the HIBP Pwned Passwords API
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url)

        if response.status_code == 200:
            # Check if the password suffix exists in the response
            return suffix in response.text
        else:
            # Handle other status codes, you may choose to log an error or raise an exception
            return False
        
    def validate_password(self, password):
        passw = password.data
        passw_without_spaces = re.sub(' +', ' ', passw)  # Replace consecutive multiple spaces with a single space
        password_strength = zxcvbn(passw_without_spaces)

        pattern = re.compile(r'^[\u0020-\uD7FF\uE000-\uFFFD\u10000-\u10FFF]*$') # Match any printable Unicode character, including language neutral characters such as spaces and Emojis

        if self.is_password_pwned(passw_without_spaces):
            raise ValidationError('This password has been compromised. Choose a different one.')

        if password_strength['score'] < 3:
            raise ValidationError(f'This password is not strong enough. {password_strength["feedback"]["suggestions"]}')
        

        if not pattern.match(passw_without_spaces):
            raise ValidationError('Password must only contain printable Unicode characters.')

        if len(passw_without_spaces) < 12:
            raise ValidationError('Password must be at least 12 characters long.')
        
        if len(passw_without_spaces) > 128:
            raise ValidationError('Password must be no longer than 128 characters.')
        
        #if not any(char.isdigit() for char in passw_without_spaces):
        #    raise ValidationError('Password must contain at least one digit.')
            
        #if not any(char.isupper() for char in passw_without_spaces):
        #    raise ValidationError('Password must contain at least one uppercase letter.')
            
        #if not any(char.islower() for char in passw_without_spaces):
        #    raise ValidationError('Password must contain at least one lowercase letter.')
            
        # if not re.search(r"[~\!@#\$%\^&\*\(\)_\+{}:;\[\]]", passw_without_spaces):
        #     raise ValidationError(f'Password must contain at least one special character. {special_chars}')
            
        
        return True

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=12, max=128)], render_kw={"placeholder": "Password"})
    remember = BooleanField('remember me')
    
    submit = SubmitField('Login')

    def validate_username(self, username):
        if not re.match("^[a-zA-Z0-9]+$", username.data):
            raise ValidationError('Invalid Username. Please try again.')

#new
class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators = [InputRequired(), Email(message = 'Invalid email'), Length(max = 50)], render_kw={"placeholder": "Email"})
    full_name = StringField('Full name', validators = [InputRequired(), Length(min = 3, max = 50)], render_kw={"placeholder": "Full name"})
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other'), ('Prefer not to say', 'Prefer not to say')])
    submit = SubmitField('Update')

    # CWE-20: Improper Input Validation
    def validate_username(self, username):
        if username.data != current_user.username:
            existing_username = User.query.filter_by(username = username.data).first()
            if existing_username:
                raise ValidationError('Username already exists. Please choose another one.')
            
            if not re.match("^[a-zA-Z0-9]+$", username.data):
                raise ValidationError('Username can only contain alphanumeric characters.')

    def validate_email(self, email):
        if email.data != current_user.email:
            existing_email = User.query.filter_by(email = email.data).first()
            if existing_email:
                raise ValidationError('Email already exists. Please choose another one.')
            
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email.data):
                raise ValidationError('Invalid email. Please try again.')

#new
class UpdatePassword(FlaskForm):
    password = PasswordField('Password', render_kw={"placeholder": "Password"})
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=12, max=128)], render_kw={"placeholder": "New Password"})
    submit = SubmitField('Update')
   
    def is_password_pwned(self, new_password):
        password = new_password
        password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = password[:5], password[5:]

        # Make a request to the HIBP Pwned Passwords API
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url)

        if response.status_code == 200:
            # Check if the password suffix exists in the response
            return suffix in response.text
        else:
            # Handle other status codes, you may choose to log an error or raise an exception
            return False
        
    def validate_new_password(self, new_password):
        passw = new_password.data

        passw_without_spaces = re.sub(' +', ' ', passw)  # Replace consecutive multiple spaces with a single space
        password_strength = zxcvbn(passw_without_spaces)

        pattern = re.compile(r'^[\u0020-\uD7FF\uE000-\uFFFD\u10000-\u10FFF]*$') # Match any printable Unicode character, including language neutral characters such as spaces and Emojis

        if self.is_password_pwned(passw_without_spaces):
            raise ValidationError('This password has been compromised. Choose a different one.')

        if password_strength['score'] < 3:
            raise ValidationError(f'This password is not strong enough. {password_strength["feedback"]["suggestions"]}')

        if not pattern.match(passw_without_spaces):
            raise ValidationError('Password must only contain printable Unicode characters.')

        if len(passw_without_spaces) < 12:
            raise ValidationError('Password must be at least 12 characters long.')
        
        if len(passw_without_spaces) > 128:
            raise ValidationError('Password must be no longer than 128 characters.')
        
        return True
    
#new
class AdminForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=12, max=128)], render_kw={"placeholder": "Password"})
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    submit = SubmitField('Delete user')

#new
class DeleteAccount(FlaskForm):
    password = PasswordField('Password', render_kw={"placeholder": "Password"})
    submit = SubmitField('Delete Account')
   
#new
class ExportData(FlaskForm):
    password = PasswordField('Password', render_kw={"placeholder": "Password"})
    submit = SubmitField('Export Data')
  
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    price = db.Column(db.Integer)  # in cents
    stock = db.Column(db.Integer)
    description = db.Column(db.String(500))
    image = db.Column(db.String(100))

    orders = db.relationship('Order_Item', backref='product', lazy=True)
    def in_stock(self):
        if 'cart' in session:
            items = session['cart']
            for item in items:
                if item.get('id') == self.id:
                    return self.stock - item.get('quantity', 0)
        return self.stock

    @classmethod    
    def add_product(cls, id, name, price, stock, description, image):
        new_product = cls(
            id=id,
            name=name,
            price=price,
            stock=stock,
            description=description,
            image=image
        )
        db.session.add(new_product)  # Make sure to use SQLAlchemy session
        db.session.commit()
    
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(255), nullable=True)

    
class Order_Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)

class AddToCart(FlaskForm):
    id = IntegerField('ID')
    quantity = IntegerField('Quantity')
    

def handle_cart():

    if 'cart' not in session:
        return [], 0, 0
    
    products = []
    grand_total = 0
    index = 0
    quantity_total = 0

    for item in session['cart']:
        product = Product.query.filter_by(id=item['id']).first()

        quantity = int(item['quantity'])
        total = quantity * product.price
        grand_total += total

        quantity_total += quantity

        products.append({'id': product.id, 'name': product.name, 'price':  product.price,
                         'image': product.image, 'quantity': quantity, 'total': total, 'index': index})
        index += 1

    return products, grand_total,quantity_total
# -------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('logout.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    global key, hash_key

    form = LoginForm()
    if form.validate_on_submit():
       user = User.query.filter_by(username = form.username.data).first()
       if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember = form.remember.data)
            with open('keys.csv', 'r', newline='') as file:
                reader_file = reader(file)
                for row in reader_file:
                    if row and row[0] == user.username:
                        key = ast.literal_eval(row[1])
                        hash_key = ast.literal_eval(row[2])   

            print(decrypt_with_hmac(key, hash_key, user.email))
            return redirect(url_for('catalog'))
       else:
           session.pop('_flashes', None)  # clear all flash messages
           flash('Invalid username or password')
    return render_template('login.html', form = form)

@app.route('/catalog')
@login_required
def catalog():
    products = Product.query.all()
    return render_template('catalog.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if  form.validate_on_submit():
        admin = False
        if "TartarugaAdmin" in form.password.data:
            admin = True
        key_reg = generate_key()
        hash_key_reg = generate_key()
        info = [form.username.data, key_reg, hash_key_reg]
        with open('keys.csv', 'a') as f_object:
            writer_object = writer(f_object)
            writer_object.writerow(info)
            f_object.close()
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        encrypted_email = encrypt_with_hmac(key_reg, form.email.data, hash_key_reg)
        encrypted_gender = encrypt_with_hmac(key_reg, form.gender.data, hash_key_reg)
        encrypted_full_name = encrypt_with_hmac(key_reg, form.full_name.data, hash_key_reg)
        new_user = User(username=form.username.data, password=hashed_password, gender=encrypted_gender, full_name=encrypted_full_name, email=encrypted_email, admin=admin)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# new 
@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = encrypt_with_hmac(key, form.email.data, hash_key)
        current_user.full_name = encrypt_with_hmac(key, form.full_name.data, hash_key)
        current_user.gender = encrypt_with_hmac(key, form.gender.data, hash_key)
        db.session.commit()
        
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        print(key)
        print(hash_key)
        form.email.data = decrypt_with_hmac(key, hash_key, current_user.email)
        form.full_name.data = decrypt_with_hmac(key, hash_key, current_user.full_name)
        form.gender.data = decrypt_with_hmac(key, hash_key, current_user.gender)
        form.username.data = current_user.username
    return render_template('account.html', form = form)

#new
@app.route("/admin", methods=['GET', 'POST'])
@login_required
def admin():
    form = AdminForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and bcrypt.check_password_hash(current_user.password, form.password.data):
            db.session.delete(user)
            db.session.commit()
            flash('User deleted!', 'success')
            return redirect(url_for('admin'))
        else:
            session.pop('_flashes', None)
            flash('Invalid password')
    return render_template('admin.html', form = form)

#new
@app.route("/delete_users", methods=['GET', 'POST'])
@login_required
def delete_users():
    order_user_ids = {order.id_user for order in Order.query.all()}
    users = User.query.all()
    for user in users:
        if user.id not in order_user_ids:
            if user.admin == False:
                db.session.delete(user)

    db.session.commit()
    flash('Users with no orders deleted!', 'success')
    return redirect(url_for('admin'))

#new
@app.route("/delete_account", methods=['POST', 'GET'])
@login_required
def delete_account():
    form = DeleteAccount()
    if form.validate_on_submit():
        user = User.query.filter_by(username = current_user.username).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            db.session.delete(user)
            db.session.commit()
            flash('Your account has been deleted!', 'success')
            return redirect(url_for('home'))
        else:
            session.pop('_flashes', None)
            flash('Invalid password')
    return render_template('delete_account.html', form = form)

#new
@app.route("/export_data", methods=['POST', 'GET'])
@login_required
def export_data():
    form = ExportData()
    if form.validate_on_submit():
        user = User.query.filter_by(username = current_user.username).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # Prepare user data
            user_data = {
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "gender": user.gender
            }

            # Convert user data to JSON and save it to a file
            with open('user_data.json', 'w') as f:
                json.dump(user_data, f)

            # Send file as download response
            return send_file('user_data.json', as_attachment=True)

        else:
            session.pop('_flashes', None)
            flash('Invalid password')
    return render_template('export_data.html', form=form)

#new
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = UpdatePassword()
    if form.validate_on_submit():
        user = User.query.filter_by(username = current_user.username).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            hashed_password = bcrypt.generate_password_hash(form.new_password.data)
            current_user.password = hashed_password
            db.session.commit()
            flash('Your pass has been updated!', 'success')
            return redirect(url_for('account'))
        else:
            session.pop('_flashes', None)  # clear all flash messages
            print('Invalid password')
            flash('Invalid password')
    return render_template('change_password.html', form = form)

@app.errorhandler(404)
def page_not_found(e):
    print(e)
    return render_template('404.html')

@app.route('/product/<int:product_id>')
@login_required
def product(product_id):
    product = Product.query.get(product_id)
    reviews = Review.query.filter_by(product_id=product_id).all()
    form = AddToCart()
    session['last_product_id'] = product_id 

    
    return render_template('product.html', product=product, reviews=reviews, form=form)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def cart():
    products, grand_total, quantity_total = handle_cart()
    print(products)
    return render_template('cart.html', products=products, grand_total=grand_total, quantity_total=quantity_total)

    
@app.route('/quick-add/<id>')
def quick_add(id):
    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'id': id, 'quantity': 1})
    print(session['cart'])
    session.modified = True

    return redirect(url_for('catalog'))

@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []

    form = AddToCart()

    if form.validate_on_submit():

        session['cart'].append(
            {'id': form.id.data, 'quantity': form.quantity.data})
        print(session['cart'])
        session.modified = True

    return redirect(url_for('catalog'))

@app.route('/remove-from-cart/<index>')
@login_required
def remove_from_cart(index):
    del session['cart'][int(index)]
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/empty')
@login_required
def empty_cart():
    try:
        session.pop('cart', None)  # Remove the 'cart' key from the Flask session
        flash("Your cart has been emptied.", "success")
    except Exception as e:
        print(e)
    return redirect(url_for('cart'))

def validate_date_format(form, field):
    if not re.match(r'\d{2}/\d{2}', field.data):
        raise ValidationError('Card Expiration must be in the format MM/YY.')
def required_if_credit_card(form, field):
    if form.payment_method.data == 'Credit Card' and not field.data:
        raise ValidationError('This field is required.')
def required_if_paypal(form, field):
    if form.payment_method.data == 'Paypal' and not field.data:
        raise ValidationError('This field is required.')
def required_if_mbway(form, field):
    if form.payment_method.data == 'MBWay' and not field.data:
        raise ValidationError('This field is required.')

class CheckoutForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "e.g. Jhon"})
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "e.g. Doe"})
    phone_number = StringField('Phone Number', validators=[InputRequired(), Length(min=9, max=9)], render_kw={"placeholder": "e.g. 912345678"})
    email = StringField('Email', validators=[InputRequired(), Email()], render_kw={"placeholder": "e.g. email@ua.pt"})
    address = StringField('Address', validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder": "e.g. Cristiano Ronaldo Street 7"})
    city = StringField('City', validators=[InputRequired(), Length(min=2, max=100)])
    country = StringField('Country', validators=[InputRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=12, max=128)], render_kw={"placeholder": "Password"})
    payment_method = SelectField('Payment Method', validators=[InputRequired()], choices=[('Credit Card', 'Credit Card'), ('Multibanco', 'Multibanco'), ('Paypal', 'Paypal'), ('MBWay', 'MBWay')])
    card_number = StringField('Card Number', validators=[Optional(), Length(min=16, max=16), required_if_credit_card], render_kw={"placeholder": "XXXX XXXX XXXX XXXX"})
    expiration_date = StringField('Card Expiration', validators=[Optional(), validate_date_format, required_if_credit_card], render_kw={"placeholder": "MM/YY"})
    cvv = StringField('Card CVV', validators=[Optional(), Length(min=3, max=3), required_if_credit_card], render_kw={"placeholder": "XXX"})
    paypal_email = StringField('PayPal Email', validators=[Optional(), Email(), required_if_paypal], render_kw={"placeholder": "paypal@email.com"})
    mbway_phone_number = StringField('Phone Number', validators=[Optional(), Length(min=9, max=9), required_if_mbway], render_kw={"placeholder": "e.g. 912345678"})

    submit = SubmitField('Checkout')

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = CheckoutForm()
    if form.validate_on_submit():
        if not bcrypt.check_password_hash(current_user.password, form.password.data):
            flash("Invalid password", "danger")
            return redirect(url_for('checkout'))
        user = User.query.filter_by(username = current_user.username).first()
        ref = str(random.randint(10000, 99999))
        products, grand_total, quantity_total = handle_cart()
        if user:
            encrypted_first_name = encrypt_with_hmac(key, form.first_name.data, hash_key)
            encrypted_last_name = encrypt_with_hmac(key, form.last_name.data, hash_key)
            encrypted_phone_number = encrypt_with_hmac(key, form.phone_number.data, hash_key)
            encrypted_email = encrypt_with_hmac(key, form.email.data, hash_key)
            encrypted_address = encrypt_with_hmac(key, form.address.data, hash_key)
            encrypted_city = encrypt_with_hmac(key, form.city.data, hash_key)
            encrypted_country = encrypt_with_hmac(key, form.country.data, hash_key)

            order = Order(
                id_user=user.id,
                reference=ref,
                first_name=encrypted_first_name,
                last_name=encrypted_last_name,
                phone_number=encrypted_phone_number,
                email=encrypted_email,
                address=encrypted_address,
                city=encrypted_city,
                country=encrypted_country,
                status="New",  # or whatever default status
            )

            if form.payment_method.data == 'Credit Card':
                order.card_number = encrypt_with_hmac(key, form.card_number.data, hash_key)
                order.expiration_date = encrypt_with_hmac(key, form.expiration_date.data, hash_key)
                order.cvv = encrypt_with_hmac(key, form.cvv.data, hash_key)
            elif form.payment_method.data == 'Paypal':
                order.paypal_email = encrypt_with_hmac(key, form.paypal_email.data, hash_key)
            elif form.payment_method.data == 'MBWay':
                order.mbway_phone_number = encrypt_with_hmac(key, form.mbway_phone_number.data, hash_key)

            db.session.add(order)
            db.session.flush()  # Force SQLAlchemy to INSERT the order
            db.session.commit()
        
        order = Order.query.filter_by(reference = ref).first()
        
        flash("Order created successfully, generating receipt!")
        return redirect(url_for('receipt', order_id=order.id))
    return render_template('checkout.html', form=form, user=current_user)
        
@app.route('/receipt/<order_id>')
@login_required
def receipt(order_id):
    order = Order.query.filter_by(id=order_id).first()
    
    # if the order is encrypted, it will have a ":"
    if ":" in order.first_name:
        order.first_name = decrypt_with_hmac(key, hash_key, order.first_name)
        order.last_name = decrypt_with_hmac(key, hash_key, order.last_name)
        order.email = decrypt_with_hmac(key, hash_key, order.email)
        order.address = decrypt_with_hmac(key, hash_key, order.address)
        order.city = decrypt_with_hmac(key, hash_key, order.city)
        order.country = decrypt_with_hmac(key, hash_key, order.country)
    
    products, grand_total, quantity_total = handle_cart()
    if order is None:
        return "No order found", 404
    # Add the products to the order
    for product in products:
        order_item = Order_Item(order_id=order.id, product_id=product['id'], quantity=product['quantity'])
        db.session.add(order_item)
    db.session.commit()
    return render_template('receipt.html', order=order, products=products, grand_total=grand_total, quantity_total=quantity_total)

@app.route('/past-orders')
@login_required
def past_orders():
    user_id = current_user.id
    orders = Order.query.filter_by(id_user=user_id).all()
    if not orders:
        return render_template('past_orders.html', orders=orders)
    
    # decrypt orders
    for order in orders:
        if ":" in order.first_name:
            order.first_name = decrypt_with_hmac(key, hash_key, order.first_name)
            order.last_name = decrypt_with_hmac(key, hash_key, order.last_name)
            order.address = decrypt_with_hmac(key, hash_key, order.address)
            order.city = decrypt_with_hmac(key, hash_key, order.city)
            order.country = decrypt_with_hmac(key, hash_key, order.country)
    
    return render_template('past_orders.html', orders=orders)

@app.route('/reorder/<order_id>')
@login_required
def reorder(order_id):
    user_id = current_user.id  # Get the current user's ID from Flask-Login
    order = Order.query.filter_by(id=order_id, id_user=user_id).first()
    for item in order.items:
        product = item.product
        if product.in_stock() > 0:
            if 'cart' not in db.session:
                db.session['cart'] = []
            db.session['cart'].append({'id': product.id, 'quantity': item.quantity})
            db.session.modified = True

    flash("Order successfully added to the cart. You can now review and complete the order.", "success")
    return redirect(url_for('cart'))

# @app.route('/show_alert')
# @login_required
# def show_alert():
#     flash("Your cart is empty! Please add some items and try again.", "danger")
#     return render_template('alert.html')

@app.route('/add_review', methods=['POST'])
@login_required
def add_review():
    try:
        product_id = request.form.get('product_id')
        rating = request.form.get('rating')
        comment = request.form.get('comment')
                                   
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            if file.content_length < app.config['MAX_CONTENT_LENGTH']:
                # Process the file (save to disk, perform actions, etc.)
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        elif file and not allowed_file(file.filename):
            flash('Invalid file type. Allowed types are jpg, png, and gif.', 'error')

        review = Review(product_id=product_id, rating=rating, comment=comment)
        db.session.add(review)
        db.session.commit()

        return redirect(url_for('product', product_id=product_id))
    except Exception as e:
        print(f"Exception: {e}")
        raise
 
   
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash('The data value transmitted exceeds the capacity limit (2 MB).', 'error')
    product_id = session.get('last_product_id') 
    if product_id:
        return redirect(url_for('product', product_id=product_id))
    else:
        return redirect(url_for('catalog'))


# issue 4.1.5
@app.errorhandler(404)
def page_not_found(e):
	logging.error(f"Page not found: {e}")
	return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
	logging.error(f"Forbidden: {e}")
	return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Internal Server Error: {e}")
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(e):
    logging.error(f"Bad Request: {e}")
    return render_template('400.html'), 400

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'png', 'gif'}

if __name__ == '__main__':
    app.run(debug=True)

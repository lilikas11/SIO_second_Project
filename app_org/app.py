# Importações
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import random
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import SelectField, StringField, PasswordField, BooleanField, SubmitField, IntegerField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError, Email, Optional
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms.widgets import HiddenInput

# Configurações do aplicativo Flask
app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "catalog" 

app.config['SECRET_KEY'] = 'Tartaruga_Clastrofobica'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # Use um banco de dados real em produção
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

#Database models
# Modelo de Usuário
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer)
    reference = db.Column(db.String(5))
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(50))
    address = db.Column(db.String(100))
    city = db.Column(db.String(100))
    country = db.Column(db.String(20))
    status = db.Column(db.String(10))
    payment_type = db.Column(db.String(10))
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
    def add_order(cls, id_user, reference, first_name, last_name, phone_number, email, address, city, country, status, payment_type):
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
            payment_type=payment_type
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
    username = db.Column(db.String(15), unique = True, nullable = False)
    password = db.Column(db.String(80), nullable = False)
    gender = db.Column(db.String(10), nullable = False)
    full_name = db.Column(db.String(80), nullable = False)
    email = db.Column(db.String(50), unique = True, nullable = False)
    admin = db.Column(db.Boolean, default = False)

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    gender = SelectField('Gender', choices=(('Male'),('Female'),('Other'),('Prefer not to say')))
    email = StringField('Email', validators = [InputRequired(), Email(message = 'Invalid email'), Length(max = 50)], render_kw={"placeholder": "Email"})
    full_name = StringField('Full name', validators = [InputRequired(), Length(min = 3, max = 50)], render_kw={"placeholder": "Full name"})
    submit = SubmitField('Register')

    # CWE-20: Improper Input Validation
    def validate_username(self, username):
        existing_username = User.query.filter_by(username = username.data).first()
        if existing_username:
            raise ValidationError('Username already exists. Please choose another one.')
        
        if not re.match("^[a-zA-Z0-9]+$", username.data):
            raise ValidationError('Username can only contain alphanumeric characters.')

    def validate_password(self, password):
        passw = password.data
        special_chars = "~!@#$%^&*()_+{}:;[]"
            
        if len(passw) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
            
        if not any(char.isdigit() for char in passw):
            raise ValidationError('Password must contain at least one digit.')
            
        if not any(char.isupper() for char in passw):
            raise ValidationError('Password must contain at least one uppercase letter.')
            
        if not any(char.islower() for char in passw):
            raise ValidationError('Password must contain at least one lowercase letter.')
            
        if not re.search(r"[~\!@#\$%\^&\*\(\)_\+{}:;\[\]]", passw):
            raise ValidationError(f'Password must contain at least one special character. {special_chars}')
            
        if re.search(r"[^a-zA-Z0-9" + re.escape(special_chars) + "]", passw):
            raise ValidationError(f'Password contains invalid character.\nOnly alphanumeric characters and these special characters are allowed: {special_chars}')
            
        return True

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    remember = BooleanField('remember me')
    
    submit = SubmitField('Login')

    def validate_username(self, username):
        if not re.match("^[a-zA-Z0-9]+$", username.data):
            raise ValidationError('Invalid Username. Please try again.')


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
    products = []
    grand_total = 0
    index = 0
    quantity_total = 0

    if 'cart' not in session or not session['cart']:
        return [], 0, 0
    else:
        for item in session['cart']:
            print(session['cart'])
            product = Product.query.filter_by(id=item['id']).first()
            if item in session['cart']:
                quantity = int(item['quantity'])
                total = quantity * product.price
                grand_total += total

                quantity_total += quantity

                products.append({'id': product.id, 'name': product.name, 'price': product.price, 'image': product.image, 'quantity': quantity, 'total': total, 'index': index})
                index += 1
        return products, grand_total, quantity_total

@app.route('/')
def home():
    return render_template('logout.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
       user = User.query.filter_by(username = form.username.data).first()
       if user and bcrypt.check_password_hash(user.password, form.password.data):
           login_user(user, remember = form.remember.data)
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
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, gender=form.gender.data, full_name=form.full_name.data, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

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
    
    return render_template('product.html', product=product, reviews=reviews, form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/logout')
@login_required
def logout():
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def cart():
    # cart_data = handle_cart()
    # if isinstance(cart_data, list) and len(cart_data) == 4:
    #     products, grand_total, quantity_total = cart_data
    #     return render_template('cart.html', products=products, grand_total=grand_total, quantity_total=quantity_total)
    # else:
    #     return cart_data
    products, grand_total, quantity_total = handle_cart()
    return render_template('cart.html', products=products, grand_total=grand_total, quantity_total=quantity_total)

    
@app.route('/quick-add/<id>')
def quick_add(id):
    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'id': id, 'quantity': 1})
    session.modified = True

    return redirect(url_for('catalog'))

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    form = AddToCart()

    if form.validate_on_submit():
        if 'cart' not in session:
            session['cart'] = []
            
        product_id = form.id.data
        quantity = form.quantity.data

        session['cart'].append(
            {'id': product_id, 'quantity': quantity})
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
        user = User.query.filter_by(email = form.email.data).first()
        ref = str(random.randint(10000, 99999))
        products, grand_total, quantity_total = handle_cart()
        if user:
            # create order and add it to database
            Order.add_order(
            id_user=user.id,
            reference=ref,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            phone_number=form.phone_number.data,
            email=form.email.data,
            address=form.address.data,
            city=form.city.data,
            country=form.country.data,
            status="New",  # or whatever default status
            payment_type=form.payment_method.data
            )
            
        # get order from database
        order = Order.query.filter_by(reference = ref).first()
        
        flash("Order created successfully, generating receipt!")
        return redirect(url_for('receipt', order_id=order.id))
    return render_template('checkout.html', form=form, user=current_user)
        
@app.route('/receipt/<order_id>')
@login_required
def receipt(order_id):
    order = Order.query.filter_by(id=order_id).first()
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
    user_id = current_user.id  # Get the current user's ID from Flask-Login
    orders = Order.query.filter_by(id_user=user_id).all()
    if not orders:
        flash("You have no past orders.", "danger")
        return redirect(url_for('catalog'))
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
    product_id = request.form.get('product_id')
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
    review = Review(product_id=product_id, rating=rating, comment=comment)
    db.session.add(review)
    db.session.commit()

    return redirect(url_for('product', product_id=product_id))



if __name__ == '__main__':
    app.run(debug=True)

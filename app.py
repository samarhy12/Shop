from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func
import os
from functools import wraps

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ecommerce.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['ITEMS_PER_PAGE'] = 12
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
CORS(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    orders = db.relationship('Order', backref='user', lazy=True)
    wishlist = db.relationship('WishlistItem', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    children = db.relationship('Category', backref=db.backref('parent', remote_side=[id]))
    products = db.relationship('Product', backref='category', lazy=True)
    image_path = db.Column(db.String(255))
    is_featured = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    sale_price = db.Column(db.Float)
    stock = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    images = db.relationship('ProductImage', backref='product', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_featured = db.Column(db.Boolean, default=False)
    specifications = db.relationship('ProductSpecification', backref='product', lazy=True)
    reviews = db.relationship('ProductReview', backref='product', lazy=True)
    tags = db.relationship('Tag', secondary='product_tags', backref='products')

class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    alt_text = db.Column(db.String(100))

class ProductSpecification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(100), nullable=False)

class ProductReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)

product_tags = db.Table('product_tags',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    total_amount = db.Column(db.Float, nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    shipping_method = db.Column(db.String(50), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)
    tracking_number = db.Column(db.String(100))

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class WishlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Cart Management
class Cart:
    def __init__(self):
        self.items = {}
        self.total = 0.0
    
    def add_item(self, product_id, quantity=1):
        product = Product.query.get(product_id)
        if not product:
            return False
        
        if product_id in self.items:
            self.items[product_id]['quantity'] += quantity
        else:
            self.items[product_id] = {
                'product': product,
                'quantity': quantity,
                'price': product.sale_price or product.price
            }
        
        self.update_total()
        return True
    
    def remove_item(self, product_id):
        if product_id in self.items:
            del self.items[product_id]
            self.update_total()
    
    def update_quantity(self, product_id, quantity):
        if product_id in self.items and quantity > 0:
            self.items[product_id]['quantity'] = quantity
            self.update_total()
    
    def update_total(self):
        self.total = sum(item['price'] * item['quantity'] for item in self.items.values())
    
    def clear(self):
        self.items = {}
        self.total = 0.0

def init_cart():
    if 'cart' not in session:
        session['cart'] = Cart().__dict__

# Template Routes

@app.route('/')
def home():
    featured_categories = Category.query.filter_by(is_featured=True).limit(4).all()
    featured_products = Product.query.filter_by(is_featured=True).limit(8).all()
    newest_products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    
    return render_template('home.html',
                         featured_categories=featured_categories,
                         featured_products=featured_products,
                         newest_products=newest_products)

@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    category_slug = request.args.get('category')
    search_query = request.args.get('q')
    sort_by = request.args.get('sort', 'created_at')
    
    query = Product.query
    
    if category_slug:
        category = Category.query.filter_by(slug=category_slug).first()
        if category:
            query = query.filter_by(category_id=category.id)
    
    if search_query:
        query = query.filter(
            or_(
                Product.name.ilike(f'%{search_query}%'),
                Product.description.ilike(f'%{search_query}%')
            )
        )
    
    if sort_by == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_desc':
        query = query.order_by(Product.price.desc())
    else:
        query = query.order_by(Product.created_at.desc())
    
    products = query.paginate(page=page, per_page=app.config['ITEMS_PER_PAGE'])
    categories = Category.query.all()
    
    return render_template('products/list.html',
                         products=products,
                         categories=categories,
                         category_slug=category_slug,
                         search_query=search_query,
                         sort_by=sort_by)

@app.route('/product/<slug>')
def product_detail(slug):
    product = Product.query.filter_by(slug=slug).first_or_404()
    related_products = Product.query.filter_by(category_id=product.category_id)\
        .filter(Product.id != product.id)\
        .limit(4).all()
    
    return render_template('products/detail.html',
                         product=product,
                         related_products=related_products)

@app.route('/cart')
def cart():
    init_cart()
    cart_data = Cart()
    cart_data.__dict__ = session['cart']
    return render_template('cart.html', cart=cart_data)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def cart_add(product_id):
    init_cart()
    quantity = int(request.form.get('quantity', 1))
    
    cart_data = Cart()
    cart_data.__dict__ = session['cart']
    
    if cart_data.add_item(product_id, quantity):
        session['cart'] = cart_data.__dict__
        flash('Product added to cart successfully!', 'success')
    else:
        flash('Failed to add product to cart.', 'error')
    
    return redirect(request.referrer or url_for('cart'))

@app.route('/cart/update/<int:product_id>', methods=['POST'])
def cart_update(product_id):
    init_cart()
    quantity = int(request.form.get('quantity', 0))
    
    cart_data = Cart()
    cart_data.__dict__ = session['cart']
    
    if quantity > 0:
        cart_data.update_quantity(product_id, quantity)
    else:
        cart_data.remove_item(product_id)
    
    session['cart'] = cart_data.__dict__
    return redirect(url_for('cart'))

@app.route('/cart/remove/<int:product_id>', methods=['POST'])
def cart_remove(product_id):
    init_cart()
    cart_data = Cart()
    cart_data.__dict__ = session['cart']
    cart_data.remove_item(product_id)
    session['cart'] = cart_data.__dict__
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    init_cart()
    cart_data = Cart()
    cart_data.__dict__ = session['cart']
    
    if request.method == 'POST':
        if not cart_data.items:
            flash('Your cart is empty.', 'error')
            return redirect(url_for('cart'))
        
        # Create order
        order = Order(
            user_id=current_user.id,
            total_amount=cart_data.total,
            shipping_address=request.form['shipping_address'],
            shipping_method=request.form['shipping_method'],
            payment_method=request.form['payment_method']
        )
        db.session.add(order)
        
        # Create order items
        for product_id, item in cart_data.items.items():
            order_item = OrderItem(
                order=order,
                product_id=product_id,
                quantity=item['quantity'],
                price=item['price']
            )
            db.session.add(order_item)
            
            # Update product stock
            product = Product.query.get(product_id)
            product.stock -= item['quantity']
        
        db.session.commit()
        
        # Clear cart
        cart_data.clear()
        session['cart'] = cart_data.__dict__
        
        flash('Order placed successfully!', 'success')
        return redirect(url_for('order_confirmation', order_id=order.id))
    
    return render_template('checkout.html',
                         cart=cart_data,
                         user=current_user)

@app.route('/order/confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return render_template('orders/confirmation.html', order=order)

@app.route('/orders')
@login_required
def orders():
    page = request.args.get('page', 1, type=int)
    orders = Order.query.filter_by(user_id=current_user.id)\
        .order_by(Order.created_at.desc())\
        .paginate(page=page, per_page=10)
    return render_template('orders/list.html', orders=orders)

@app.route('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return render_template('orders/detail.html', order=order)

@app.route('/wishlist')
@login_required
def wishlist():
    items = WishlistItem.query.filter_by(user_id=current_user.id).all()
    return render_template('wishlist.html', items=items)

@app.route('/wishlist/add/<int:product_id>', methods=['POST'])
@login_required
def wishlist_add(product_id):
    if not WishlistItem.query.filter_by(
        user_id=current_user.id,
        product_id=product_id
    ).first():
        item = WishlistItem(user_id=current_user.id, product_id=product_id)
        db.session.add(item)
        db.session.commit()
        flash('Product added to wishlist!', 'success')
    return redirect(request.referrer or url_for('products'))

@app.route('/wishlist/remove/<int:product_id>', methods=['POST'])
@login_required
def wishlist_remove(product_id):
    WishlistItem.query.filter_by(
        user_id=current_user.id,
        product_id=product_id
    ).delete()
    db.session.commit()
    flash('Product removed from wishlist!', 'success')
    return redirect(request.referrer or url_for('wishlist'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=request.form.get('remember', False))
            next_page = request.args.get('next')
            flash('Logged in successfully!', 'success')
            return redirect(next_page or url_for('home'))
        flash('Invalid email or password.', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first():
            flash('Email already registered.', 'error')
        else:
            user = User(
                email=request.form['email'],
                first_name=request.form['first_name'],
                last_name=request.form['last_name'],
                phone=request.form['phone'],
                address=request.form['address'],
                city=request.form['city'],
                country=request.form['country'],
                postal_code=request.form['postal_code']
            )
            user.set_password(request.form['password'])
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        current_user.phone = request.form['phone']
        current_user.address = request.form['address']
        current_user.city = request.form['city']
        current_user.country = request.form['country']
        current_user.postal_code = request.form['postal_code']
        
        if request.form.get('password'):
            current_user.set_password(request.form['password'])
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)

@app.route('/api/auth/register', methods=['POST'])
def register_api():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    user = User(
        email=data['email'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        phone=data['phone'],
        address=data['address'],
        city=data['city'],
        country=data['country'],
        postal_code=data['postal_code']
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_api():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Product routes
@app.route('/api/products', methods=['GET'])
def get_products():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    category_slug = request.args.get('category')
    search_query = request.args.get('q')
    sort_by = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')
    
    query = Product.query
    
    if category_slug:
        category = Category.query.filter_by(slug=category_slug).first()
        if category:
            # Get all subcategory IDs
            subcategory_ids = [cat.id for cat in category.children]
            subcategory_ids.append(category.id)
            query = query.filter(Product.category_id.in_(subcategory_ids))
    
    if search_query:
        query = query.filter(
            or_(
                Product.name.ilike(f'%{search_query}%'),
                Product.description.ilike(f'%{search_query}%')
            )
        )
    
    # Sorting
    if sort_by == 'price':
        query = query.order_by(Product.price.desc() if order == 'desc' else Product.price.asc())
    elif sort_by == 'name':
        query = query.order_by(Product.name.desc() if order == 'desc' else Product.name.asc())
    else:
        query = query.order_by(Product.created_at.desc() if order == 'desc' else Product.created_at.asc())
    
    products = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'items': [{
            'id': p.id,
            'name': p.name,
            'slug': p.slug,
            'price': p.price,
            'sale_price': p.sale_price,
            'category': {
                'id': p.category.id,
                'name': p.category.name,
                'slug': p.category.slug
            },
            'primary_image': next((img.image_path for img in p.images if img.is_primary), None),
            'rating': round(sum(r.rating for r in p.reviews) / len(p.reviews), 1) if p.reviews else None,
            'review_count': len(p.reviews)
        } for p in products.items],
        'total': products.total,
        'pages': products.pages,
        'current_page': products.page
    })

@app.route('/api/products/<slug>', methods=['GET'])
def get_product(slug):
    product = Product.query.filter_by(slug=slug).first_or_404()
    
    # Get related products based on category and tags
    related_products = Product.query\
        .filter(Product.category_id == product.category_id)\
        .filter(Product.id != product.id)\
        .limit(4)\
        .all()
    
    return jsonify({
        'id': product.id,
        'name': product.name,
        'slug': product.slug,
        'description': product.description,
        'price': product.price,
        'sale_price': product.sale_price,
        'stock': product.stock,
        'category': {
            'id': product.category.id,
            'name': product.category.name,
            'slug': product.category.slug
        },
        'images': [{
            'id': img.id,
            'path': img.image_path,
            'is_primary': img.is_primary,
            'alt_text': img.alt_text
        } for img in product.images],
        'specifications': [{
            'name': spec.name,
            'value': spec.value
        } for spec in product.specifications],
        'reviews': [{
            'id': review.id,
            'rating': review.rating,
            'comment': review.comment,
            'created_at': review.created_at.isoformat(),
            'user_name': f"{review.user.first_name} {review.user.last_name}"
        } for review in product.reviews],
        'tags': [{
            'id': tag.id,
            'name': tag.name,
            'slug': tag.slug
        } for tag in product.tags],
        'related_products': [{
            'id': p.id,
            'name': p.name,
            'slug': p.slug,
            'price': p.price,
            'primary_image': next((img.image_path for img in p.images if img.is_primary), None)
        } for p in related_products]
    })

# Category routes
@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = Category.query.filter_by(parent_id=None).all()
    
    def format_category(category):
        return {
            'id': category.id,
            'name': category.name,
            'slug': category.slug,
            'description': category.description,
            'image_path': category.image_path,
            'is_featured': category.is_featured,
            'subcategories': [format_category(child) for child in category.children],
            'product_count': len(category.products)
        }
    
    return jsonify([format_category(category) for category in categories])

# Orders routes
@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    # Validate items and calculate total
    total_amount = 0
    order_items = []
    
    for item in data['items']:
        product = Product.query.get_or_404(item['product_id'])
        if product.stock < item['quantity']:
            return jsonify({'error': f'Insufficient stock for {product.name}'}), 400
        
        price = product.sale_price or product.price
        total_amount += price * item['quantity']
        order_items.append({
            'product': product,
            'quantity': item['quantity'],
            'price': price
        })
    
    # Create order
    order = Order(
        user_id=user_id,
        total_amount=total_amount,
        shipping_address=data['shipping_address'],
        shipping_method=data['shipping_method'],
        payment_method=data['payment_method']
    )
    db.session.add(order)
    
    # Create order items and update stock
    for item in order_items:
        order_item = OrderItem(
            order=order,
            product_id=item['product'].id,
            quantity=item['quantity'],
            price=item['price']
        )
        item['product'].stock -= item['quantity']
        db.session.add(order_item)
    
    db.session.commit()
    
    return jsonify({'message': 'Order created successfully', 'order_id': order.id}), 201

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_user_orders():
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    orders = Order.query.filter_by(user_id=user_id)\
        .order_by(Order.created_at.desc())\
        .paginate(page=page, per_page=per_page)
    
    return jsonify({
        'orders': [{
            'id': order.id,
            'status': order.status,
            'total_amount': order.total_amount,
            'created_at': order.created_at.isoformat(),
            'tracking_number': order.tracking_number,
            'shipping_method': order.shipping_method,
            'payment_method': order.payment_method,
            'items': [{
                'product_id': item.product_id,
                'quantity': item.quantity,
                'price': item.price,
                'product_name': Product.query.get(item.product_id).name,
                'product_image': next((img.image_path for img in Product.query.get(item.product_id).images if img.is_primary), None)
            } for item in order.items]
        } for order in orders.items],
        'total': orders.total,
        'pages': orders.pages,
        'current_page': orders.page
    })

# Wishlist routes
@app.route('/api/wishlist', methods=['GET'])
@jwt_required()
def get_wishlist():
    user_id = get_jwt_identity()
    wishlist_items = WishlistItem.query.filter_by(user_id=user_id).all()
    
    return jsonify([{
        'id': item.id,
        'product': {
            'id': item.product_id,
            'name': Product.query.get(item.product_id).name,
            'slug': Product.query.get(item.product_id).slug,
            'price': Product.query.get(item.product_id).price,
            'sale_price': Product.query.get(item.product_id).sale_price,
            'primary_image': next((img.image_path for img in Product.query.get(item.product_id).images if img.is_primary), None)
        },
        'added_at': item.added_at.isoformat()
    } for item in wishlist_items])

@app.route('/api/wishlist/<int:product_id>', methods=['POST'])
@jwt_required()
def add_to_wishlist(product_id):
    user_id = get_jwt_identity()
    
    if WishlistItem.query.filter_by(user_id=user_id, product_id=product_id).first():
        return jsonify({'message': 'Product already in wishlist'}), 400
    
    wishlist_item = WishlistItem(user_id=user_id, product_id=product_id)
    db.session.add(wishlist_item)
    db.session.commit()
    
    return jsonify({'message': 'Product added to wishlist'}), 201

@app.route('/api/wishlist/<int:product_id>', methods=['DELETE'])
@jwt_required()
def remove_from_wishlist(product_id):
    user_id = get_jwt_identity()
    WishlistItem.query.filter_by(user_id=user_id, product_id=product_id).delete()
    db.session.commit()
    
    return jsonify({'message': 'Product removed from wishlist'}), 200

# Product reviews
@app.route('/api/products/<int:product_id>/reviews', methods=['POST'])
@jwt_required()
def add_review(product_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    existing_review = ProductReview.query.filter_by(
        product_id=product_id,
        user_id=user_id
    ).first()
    
    if existing_review:
        return jsonify({'error': 'You have already reviewed this product'}), 400
    
    review = ProductReview(
        product_id=product_id,
        user_id=user_id,
        rating=data['rating'],
        comment=data.get('comment', '')
    )
    
    db.session.add(review)
    db.session.commit()
    
    return jsonify({'message': 'Review added successfully'}), 201

# Product recommendations
@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    # Get featured products
    featured_products = Product.query.filter_by(is_featured=True).limit(8).all()
    
    # Get best-selling products
    best_selling = db.session.query(
        Product,
        func.sum(OrderItem.quantity).label('total_sold')
    ).join(OrderItem).group_by(Product.id)\
    .order_by(func.sum(OrderItem.quantity).desc())\
    .limit(8).all()
    
    # Get newest products
    newest_products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    
    return jsonify({
        'featured_products': [{
            'id': p.id,
            'name': p.name,
            'slug': p.slug,
            'price': p.price,
            'sale_price': p.sale_price,
            'primary_image': next((img.image_path for img in p.images if img.is_primary), None)
        } for p in featured_products],
        'best_selling': [{
            'id': p.Product.id,
            'name': p.Product.name,
            'slug': p.Product.slug,
            'price': p.Product.price,
            'sale_price': p.Product.sale_price,
            'primary_image': next((img.image_path for img in p.Product.images if img.is_primary), None),
            'total_sold': p.total_sold
        } for p in best_selling],
        'newest_products': [{
            'id': p.id,
            'name': p.name,
            'slug': p.slug,
            'price': p.price,
            'sale_price': p.sale_price,
            'primary_image': next((img.image_path for img in p.images if img.is_primary), None)
        } for p in newest_products]
    })

# User profile routes
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone': user.phone,
        'address': user.address,
        'city': user.city,
        'country': user.country,
        'postal_code': user.postal_code
    })

@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.phone = data.get('phone', user.phone)
    user.address = data.get('address', user.address)
    user.city = data.get('city', user.city)
    user.country = data.get('country', user.country)
    user.postal_code = data.get('postal_code', user.postal_code)
    
    if 'password' in data:
        user.set_password(data['password'])
    
    db.session.commit()
    
    return jsonify({'message': 'Profile updated successfully'})

@app.template_filter('currency')
def currency_filter(value):
    return f"${value:,.2f}"

@app.context_processor
def utility_processor():
    def get_cart_count():
        if 'cart' in session:
            cart_data = Cart()
            cart_data.__dict__ = session['cart']
            return sum(item['quantity'] for item in cart_data.items.values())
        return 0
    
    return dict(get_cart_count=get_cart_count)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
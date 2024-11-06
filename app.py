from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import secrets
from datetime import timedelta

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error="User with this email already exists.")
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session['username'] = user.username
            session['_user_id'] = user.id
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    items = InventoryItem.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', username=current_user.username, items=items)

@app.route('/inventory', methods=['POST'])
@login_required
def create_item():
    name = request.form['name']
    description = request.form['description']
    quantity = request.form['quantity']
    price = request.form['price']
    new_item = InventoryItem(
        name=name,
        description=description,
        quantity=quantity,
        price=price,
        user_id=current_user.id
    )
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/update_item/<int:item_id>', methods=['POST'])
@login_required
def update_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        return "Unauthorized access", 403
    item.name = request.form['name']
    item.description = request.form['description']
    item.quantity = request.form['quantity']
    item.price = request.form['price']
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        return "Unauthorized access", 403
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Run app and create tables if they don't exist
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

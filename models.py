from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    qr_code = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), default='user')
    password = db.Column(db.String(100))

class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Correct foreign key reference
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('orders', lazy=True))
    
    quantity = db.Column(db.Integer, nullable=False)
    product_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')
    
    delivery_agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Correct foreign key reference
    delivery_agent = db.relationship('User', foreign_keys=[delivery_agent_id], backref=db.backref('assigned_orders', lazy=True))

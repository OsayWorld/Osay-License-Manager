from extensions import db
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid
from flask import current_app, url_for, request
import paypalrestsdk  # PayPal SDK
import stripe  # Stripe SDK
from itsdangerous.serializer import Serializer
from sqlalchemy.ext.hybrid import hybrid_property
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask_mail import Message
from flask import render_template
from email_validator import validate_email, EmailNotValidError
import time

# Utility functions
def generate_license_key():
    return str(uuid.uuid4())

def default_usage_limit():
    return 1000

def default_license_expiry():
    return datetime.utcnow() + timedelta(days=365)

def generate_payment_token(user):
    """Generates a secure token for payments (Stripe/PayPal)"""
    s = Serializer(current_app.config['SECRET_KEY'], expires_in=3600)
    return s.dumps({'user_id': user.id}).decode('utf-8')

def send_email(subject, recipient, template, **kwargs):
    """Utility function to send emails"""
    msg = Message(subject, recipients=[recipient])
    msg.html = render_template(template, **kwargs)
    current_app.mail.send(msg)

def track_downloads(user, product):
    """Track product downloads to avoid abuse."""
    if product.download_limit is not None and product.download_count >= product.download_limit:
        raise ValueError("Download limit reached")
    product.download_count += 1
    db.session.commit()



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_developer = db.Column(db.Boolean, default=False)
    subscription_active = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)  # Two-factor authentication support
    referral_code = db.Column(db.String(10), unique=True, nullable=True)  # Affiliate program support
    profile_picture_url = db.Column(db.String(250), nullable=True)  # User profile picture for admin panel
    last_login = db.Column(db.DateTime, nullable=True)  # Store last login for security analysis
    fraud_flagged = db.Column(db.Boolean, default=False)  # Anti-fraud flag
    currency = db.Column(db.String(10), nullable=False, default="USD")  # Multi-currency support

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    licenses = db.relationship('License', backref='user', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)
    purchased_items = db.relationship('PurchasedItem', backref='user', lazy=True)
    analytics = db.relationship('Analytics', backref='user', lazy=True)
    reviews = db.relationship('Review', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    tickets = db.relationship('SupportTicket', backref='user', lazy=True)

    def set_password(self, password):
        """Hash and set the user's password"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Check if password matches"""
        return check_password_hash(self.password, password)

    def send_verification_email(self):
        """Send verification email for new users"""
        token = generate_payment_token(self)
        send_email('Verify Your Account', self.email, 'auth/verify_email.html', user=self, token=token)

    def verify_email(self, token):
        """Verify user's email using token"""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            return data.get('user_id') == self.id
        except:
            return False

    def __repr__(self):
        return f"<User {self.username}>"


class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(250), unique=True, nullable=False, default=generate_license_key)
    hashed_license_key = db.Column(db.String(250), nullable=False)  # Add hash for license security
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_suspended = db.Column(db.Boolean, default=False)
    validation_token = db.Column(db.String(250), nullable=True)  # Added for enhanced API validation

    machine_id = db.Column(db.String(100), nullable=True)
    activation_limit = db.Column(db.Integer, default=1)

    api_key = db.Column(db.String(100), nullable=True)
    usage_limit = db.Column(db.Integer, default=default_usage_limit)
    current_usage = db.Column(db.Integer, default=0)

    webhook_url = db.Column(db.String(250), nullable=True)
    subscription_id = db.Column(db.String(100), nullable=True)  # Stripe/PayPal subscription ID

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)


    whitelisted_ips = db.Column(db.String(250), nullable=True)  # IP whitelisting support for security
    transfer_allowed = db.Column(db.Boolean, default=True)  # Flag for allowing license transfer
    max_api_requests_per_day = db.Column(db.Integer, nullable=False, default=1000)  # API rate limiting

    def validate_license(self, ip=None):
        """Validate license with optional IP whitelisting"""
        if ip and ip not in self.whitelisted_ips:
            return False
        return self.is_active and not self.is_suspended and datetime.utcnow() < self.expires_at

    def increment_api_usage(self):
        if self.current_usage < self.usage_limit:
            self.current_usage += 1
            db.session.commit()
            return True
        else:
            self.is_active = False
            db.session.commit()
            return False

    def hash_license_key(self):
        """Hashes the license key for security"""
        self.hashed_license_key = hashlib.sha256(self.license_key.encode()).hexdigest()
        db.session.commit()

    def revoke_license(self):
        """Revoke a license manually."""
        self.is_active = False
        db.session.commit()

    def transfer_license(self, target_user):
        """Allow license transfer to another user"""
        self.user_id = target_user.id
        db.session.commit()

    def __repr__(self):
        return f"<License for Product {self.product_id} by User {self.user_id}>"


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    product_type = db.Column(db.String(50), nullable=False)
    license_duration_days = db.Column(db.Integer, nullable=False, default=365)
    version = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    download_file = db.Column(db.String(250), nullable=False)  # Changed to save file name
    image_file = db.Column(db.String(250), nullable=True)  # Changed to save image file name
    rating = db.Column(db.Float, nullable=True, default=0)

    category = db.Column(db.String(50), nullable=False, default="Misc")
    is_discounted = db.Column(db.Boolean, default=False)
    discount_percentage = db.Column(db.Float, nullable=True)
    bundle_products = db.Column(db.String(250), nullable=True)

    changelog = db.Column(db.Text, nullable=True)
    download_count = db.Column(db.Integer, default=0)
    download_limit = db.Column(db.Integer, default=None)

    platform = db.Column(db.String(50), nullable=False, default='Windows')

    apk_file = db.Column(db.String(250), nullable=True)  # Changed to save file name
    online_update_file = db.Column(db.String(250), nullable=True)  # Changed to save file name
    offline_update_file = db.Column(db.String(250), nullable=True)  # Changed to save file name
    script_file = db.Column(db.String(250), nullable=True)  # Changed to save file name
    remote_control_enabled = db.Column(db.Boolean, default=False)
    remote_start_file = db.Column(db.String(250), nullable=True)  # Changed to save file name
    remote_stop_file = db.Column(db.String(250), nullable=True)  # Changed to save file name

    purchase = db.Column(db.Boolean, default=False) 
    purchase_link = db.Column(db.String(250), nullable=True)  


    versions = db.relationship('ProductVersion', backref='product', lazy=True)
    reviews = db.relationship('Review', backref='product', lazy=True)
    licenses = db.relationship('License', backref='product', lazy=True)

    @hybrid_property
    def effective_price(self):
        """Calculate price considering any active discount"""
        if self.is_discounted and self.discount_percentage:
            return round(self.price * (1 - self.discount_percentage / 100), 2)
        return self.price

    def __repr__(self):
        return f"<Product {self.name}>"


class ProductVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    version_number = db.Column(db.String(50), nullable=False)
    download_url = db.Column(db.String(250), nullable=False)
    changelog = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<ProductVersion {self.version_number} for Product {self.product_id}>"


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(150), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<CartItem {self.product_name} for User {self.user_id}>"


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_total = db.Column(db.Float, nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default="Pending")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f"<Order {self.id} by User {self.user_id}>"


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(150), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)

    def __repr__(self):
        return f"<OrderItem {self.product_name} in Order {self.order_id}>"


class PurchasedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    price_at_purchase = db.Column(db.Float, nullable=False)
    software_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<PurchasedItem Software {self.software_id} by User {self.user_id}>"


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"<Notification {self.message[:30]} for User {self.user_id}>"


class Webhook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.JSON, nullable=False)
    delivered_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def process_webhook(self):
        """Process the webhook event and handle updates like license activation, refunds, etc."""
        if self.event_type == 'payment_succeeded':
            # Activate licenses
            user_id = self.payload.get('user_id')
            product_id = self.payload.get('product_id')
            subscription_id = self.payload.get('subscription_id')

            # Find the license and activate it
            license = License.query.filter_by(user_id=user_id, product_id=product_id, subscription_id=subscription_id).first()
            if license:
                license.is_active = True
                db.session.commit()

        elif self.event_type == 'subscription_cancelled':
            # Deactivate licenses
            user_id = self.payload.get('user_id')
            product_id = self.payload.get('product_id')
            subscription_id = self.payload.get('subscription_id')

            license = License.query.filter_by(user_id=user_id, product_id=product_id, subscription_id=subscription_id).first()
            if license:
                license.is_active = False
                db.session.commit()

    def __repr__(self):
        return f"<Webhook {self.event_type} for User {self.user_id}>"


class Analytics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    license_id = db.Column(db.Integer, db.ForeignKey('license.id'), nullable=True)

    def __repr__(self):
        return f"<Analytics Event {self.event_type} at {self.timestamp}>"


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Review for Product {self.product_id} by User {self.user_id}>"


class AuditLog(db.Model):
    """Stores logs of admin and user activities for auditing."""
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"<AuditLog {self.action[:30]} by User {self.user_id}>"


class SupportTicket(db.Model):
    """Support ticket for resolving user issues."""
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default="Open", nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<SupportTicket {self.subject} by User {self.user_id}>"


class FraudDetection(db.Model):
    """Added model to track fraud attempts"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    suspicious_activity = db.Column(db.String(255), nullable=False)
    flagged_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<FraudDetection Flagged for User {self.user_id}>"


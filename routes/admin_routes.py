import os
import uuid
import hashlib
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models.user import User, License, CartItem, Order, Product, Notification, FraudDetection, SupportTicket
from extensions import db
from flask import jsonify



# Configuration for file uploads

PRODUCT_CATEGORIES = {
    'MacOS_Software': 'Mac OS Software',
    'Windows_Software': 'Windows Software',
    'WordPress_Plugin': 'WordPress Plugin',
    'Chrome_Extension': 'Chrome Extension',
    'API': 'API',
    'Mobile_App': 'Mobile App',
    'Custom_Extension': 'Custom Extension',
    'APK': 'Android APK',  # New APK category
    'Offline_Update': 'Offline Update Package',
    'Online_Update': 'Online Update Package',
    'Script_Delivery': 'Script Delivery',
    'Misc': 'Miscellaneous',
    'FL_Studio_Plugin': 'FL Studio Plugin',
    'VST_Plugin': 'VST Plugin',
    'Ableton_Live_Pack': 'Ableton Live Pack',
    'Pro_Tools_Extension': 'Pro Tools Extension',
    'Photoshop_Plugin': 'Photoshop Plugin',
    'iOS_App': 'iOS Application',
    'Android_App': 'Android Application',
    'Unity_Asset': 'Unity Asset',
    'Unreal_Engine_Plugin': 'Unreal Engine Plugin',
}

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'apk', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_license_key():
    return str(uuid.uuid4())

def hash_license_key(license_key):
    return hashlib.sha256(license_key.encode()).hexdigest()

# Admin Blueprint
admin_bp = Blueprint('admin', __name__)



# Ensure that only admin users can access these routes
def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("You do not have permission to access this page.")
            return redirect(url_for('general.index'))
        return f(*args, **kwargs)
    return decorated_function

# Make user with ID 1 admin by default
@admin_bp.before_request
def ensure_user_one_is_admin():
    user = User.query.get(1)
    if user and not user.is_admin:
        user.is_admin = True
        db.session.commit()

# Admin Dashboard Route (Admin Homepage)
@admin_bp.route('/', methods=['GET'], endpoint='dashboard')
@admin_required
def dashboard():
    total_users = User.query.count()
    total_licenses = License.query.count()
    total_orders = Order.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_orders = Order.query.order_by(Order.order_date.desc()).limit(5).all()
    flagged_fraud = FraudDetection.query.count()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           total_licenses=total_licenses,
                           total_orders=total_orders,
                           recent_users=recent_users,
                           recent_orders=recent_orders,
                           flagged_fraud=flagged_fraud)

# Admin route to manage users
@admin_bp.route('/manage-users', methods=['GET', 'POST'], endpoint='manage_users')
@admin_required
def manage_users():
    users = User.query.all()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        is_developer = 'is_developer' in request.form

        new_user = User(username=username, email=email, password=password, is_admin=is_admin, is_developer=is_developer)
        db.session.add(new_user)
        db.session.commit()

        flash('User added successfully!')
        return redirect(url_for('admin.manage_users'))

    return render_template('admin/manage_users.html', users=users)

# Admin route to view detailed user activities
@admin_bp.route('/user-details/<int:user_id>', methods=['GET'], endpoint='user_details')
@admin_required
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    licenses = License.query.filter_by(user_id=user_id).all()
    cart_items = user.cart_items
    orders = user.orders
    fraud_attempts = FraudDetection.query.filter_by(user_id=user_id).all()
    notifications = Notification.query.filter_by(user_id=user_id).all()

    return render_template('admin/user_details.html', user=user, licenses=licenses, cart_items=cart_items,
                           orders=orders, fraud_attempts=fraud_attempts, notifications=notifications)


# Admin route to manage licenses
@admin_bp.route('/manage-licenses', methods=['GET', 'POST'], endpoint='manage_licenses')
@admin_required
def manage_licenses():
    licenses = License.query.all()  # Fetch all licenses
    users = User.query.all()  # Fetch all users

    if request.method == 'POST':
        # Check if the request is to generate a license key
        if 'generate_key' in request.form:
            # Generate the license key
            license_key = generate_license_key()
            return jsonify({'license_key': license_key})  # Return the key as JSON

        # Otherwise, handle license creation
        product_id = request.form['product_id']
        user_id = request.form['user_id']
        expires_at = request.form.get('expires_at', None)

        # Generate the license key if it was not generated previously
        if 'license_key' in request.form:
            license_key = request.form['license_key']
        else:
            # Generate a new license key if it was not passed in the form
            license_key = generate_license_key()

        # Hash the license key
        hashed_license_key = hashlib.sha256(license_key.encode()).hexdigest()

        # Create a new License object
        new_license = License(
            product_id=product_id,
            user_id=user_id,
            license_key=license_key,
            hashed_license_key=hashed_license_key
        )

        # Set expiration date if provided, otherwise default to 1 year
        if expires_at:
            # Convert expires_at string to a datetime object
            new_license.expires_at = datetime.strptime(expires_at, '%Y-%m-%d')
        else:
            new_license.expires_at = datetime.utcnow() + timedelta(days=365)

        # Add the license to the session and commit to the database
        db.session.add(new_license)
        db.session.commit()

        flash('License added successfully!')
        return redirect(url_for('admin.manage_licenses'))

    # Get products for license creation form
    products = Product.query.all()

    # Render the manage licenses template
    return render_template('admin/manage_licenses.html', licenses=licenses, products=products, users=users)


# Admin route to add new products
@admin_bp.route('/add-product', methods=['GET', 'POST'], endpoint='add_product')
@admin_required
def add_product():
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        product_type = request.form['product_type']
        price = float(request.form['price'])
        license_duration_days = int(request.form.get('license_duration_days', 365))
        description = request.form.get('description', '')
        category = request.form.get('category', 'Misc')
        platform = request.form.get('platform', 'Windows')
        remote_control_enabled = 'remote_control_enabled' in request.form

        # New line to retrieve the purchase_link from the form
        purchase_link = request.form.get('purchase_link', '')

        # Optional fields
        version = request.form.get('version')
        rating = float(request.form.get('rating', 0))
        is_discounted = 'is_discounted' in request.form

        # Handle discount_percentage more gracefully
        discount_percentage = request.form.get('discount_percentage', '0')
        try:
            discount_percentage = float(discount_percentage) if discount_percentage else 0.0
        except ValueError:
            discount_percentage = 0.0  # Set to 0 if there's an invalid value

        bundle_products = request.form.get('bundle_products', '')
        changelog = request.form.get('changelog', '')
        download_limit = request.form.get('download_limit')

        # Handle file uploads
        download_file = request.files.get('download_file')
        image_file = request.files.get('image_file')
        apk_file = request.files.get('apk_file')
        online_update_file = request.files.get('online_update_file')
        offline_update_file = request.files.get('offline_update_file')
        script_file = request.files.get('script_file')
        remote_start_file = request.files.get('remote_start_file')
        remote_stop_file = request.files.get('remote_stop_file')

        # Save the files (if uploaded)
        download_filename = save_file(download_file)
        image_filename = save_file(image_file)
        apk_filename = save_file(apk_file)
        online_update_filename = save_file(online_update_file)
        offline_update_filename = save_file(offline_update_file)
        script_filename = save_file(script_file)
        remote_start_filename = save_file(remote_start_file)
        remote_stop_filename = save_file(remote_stop_file)

        # Create the new product object
        new_product = Product(
            name=name,
            product_type=product_type,
            price=price,
            license_duration_days=license_duration_days,
            description=description,
            category=category,
            platform=platform,
            remote_control_enabled=remote_control_enabled,
            download_file=download_filename,
            image_file=image_filename,
            apk_file=apk_filename,
            online_update_file=online_update_filename,
            offline_update_file=offline_update_filename,
            script_file=script_filename,
            remote_start_file=remote_start_filename,
            remote_stop_file=remote_stop_filename,
            version=version,
            rating=rating,
            is_discounted=is_discounted,
            discount_percentage=discount_percentage,
            bundle_products=bundle_products,
            changelog=changelog,
            download_limit=download_limit,
            purchase_link=purchase_link  # Add the purchase link to the Product object
        )

        # Add and commit the new product to the database
        db.session.add(new_product)
        db.session.commit()

        # Flash a success message and redirect
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin.add_product'))

    # Pass PRODUCT_CATEGORIES to the template for the category dropdown
    return render_template('admin/add_product.html', PRODUCT_CATEGORIES=PRODUCT_CATEGORIES)


def save_file(file):
    """Helper function to save file if it exists and is allowed."""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return filename
    return None




# Admin route to handle support tickets
@admin_bp.route('/support-tickets', methods=['GET', 'POST'], endpoint='manage_support_tickets')
@admin_required
def manage_support_tickets():
    tickets = SupportTicket.query.all()

    if request.method == 'POST':
        user_id = request.form['user_id']
        subject = request.form['subject']
        description = request.form['description']
        status = request.form['status']

        new_ticket = SupportTicket(user_id=user_id, subject=subject, description=description, status=status)
        db.session.add(new_ticket)
        db.session.commit()

        flash('Support ticket created successfully!')
        return redirect(url_for('admin.manage_support_tickets'))

    users = User.query.all()
    return render_template('admin/manage_support_tickets.html', tickets=tickets, users=users)

# Admin route to manage cart items
@admin_bp.route('/manage-cart', methods=['GET'], endpoint='manage_cart')
@admin_required
def manage_cart():
    cart_items = CartItem.query.all()
    return render_template('admin/manage_cart.html', cart_items=cart_items)

# Admin route to manage orders
@admin_bp.route('/manage-orders', methods=['GET'], endpoint='manage_orders')
@admin_required
def manage_orders():
    orders = Order.query.all()
    return render_template('admin/manage_orders.html', orders=orders)

# Fraud detection management route
@admin_bp.route('/manage-fraud', methods=['GET'], endpoint='manage_fraud')
@admin_required
def manage_fraud():
    fraud_cases = FraudDetection.query.all()
    return render_template('admin/manage_fraud.html', fraud_cases=fraud_cases)



@admin_bp.route('/edit-product/<int:product_id>', methods=['GET', 'POST'], endpoint='edit_product')
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        # Update product details
        product.name = request.form['name']
        product.product_type = request.form['product_type']
        product.price = float(request.form['price'])
        product.license_duration_days = int(request.form.get('license_duration_days', 365))
        product.description = request.form.get('description', '')
        product.category = request.form.get('category', 'Misc')
        product.platform = request.form.get('platform', 'Windows')
        product.remote_control_enabled = 'remote_control_enabled' in request.form

        # Optional fields
        product.version = request.form.get('version')
        product.rating = float(request.form.get('rating', 0))
        product.is_discounted = 'is_discounted' in request.form
        product.discount_percentage = float(request.form.get('discount_percentage', 0))
        product.bundle_products = request.form.get('bundle_products', '')
        product.changelog = request.form.get('changelog', '')
        product.download_limit = request.form.get('download_limit')

        # Handle file uploads (if new files are uploaded)
        download_file = request.files.get('download_file')
        image_file = request.files.get('image_file')
        apk_file = request.files.get('apk_file')
        online_update_file = request.files.get('online_update_file')
        offline_update_file = request.files.get('offline_update_file')
        script_file = request.files.get('script_file')
        remote_start_file = request.files.get('remote_start_file')
        remote_stop_file = request.files.get('remote_stop_file')

        if download_file:
            product.download_file = save_file(download_file)
        if image_file:
            product.image_file = save_file(image_file)
        if apk_file:
            product.apk_file = save_file(apk_file)
        if online_update_file:
            product.online_update_file = save_file(online_update_file)
        if offline_update_file:
            product.offline_update_file = save_file(offline_update_file)
        if script_file:
            product.script_file = save_file(script_file)
        if remote_start_file:
            product.remote_start_file = save_file(remote_start_file)
        if remote_stop_file:
            product.remote_stop_file = save_file(remote_stop_file)

        # Commit changes to the database
        db.session.commit()

        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin.manage_products'))

    return render_template('admin/edit_product.html', product=product, PRODUCT_CATEGORIES=PRODUCT_CATEGORIES)



@admin_bp.route('/manage-products', methods=['GET', 'POST'], endpoint='manage_products')
@admin_required
def manage_products():
    # Get search query from request args
    search_query = request.args.get('search', '')

    # Query products with pagination and search functionality
    page = request.args.get('page', 1, type=int)
    query = Product.query

    if search_query:
        query = query.filter(Product.name.ilike(f"%{search_query}%"))

    products = query.paginate(page=page, per_page=10)

    if request.method == 'POST':
        # Handle bulk actions (e.g., deleting products)
        selected_ids = request.form.getlist('product_ids')
        if selected_ids:
            if request.form.get('action') == 'delete':
                Product.query.filter(Product.id.in_(selected_ids)).delete(synchronize_session=False)
                db.session.commit()
                flash(f"Deleted {len(selected_ids)} products", "success")

        return redirect(url_for('admin.manage_products'))

    return render_template('admin/manage_products.html', products=products)


@admin_bp.route('/product/<int:product_id>', methods=['GET'], endpoint='view_product')
@admin_required
def view_product(product_id):
    # Fetch the product by ID
    product = Product.query.get_or_404(product_id)
    
    return render_template('admin/view_product.html', product=product)



@admin_bp.route('/edit-license/<int:license_id>', methods=['GET', 'POST'], endpoint='edit_license')
@admin_required
def edit_license(license_id):
    license_to_edit = License.query.get_or_404(license_id)
    users = User.query.all()  # Fetch all users
    products = Product.query.all()  # Fetch all products

    if request.method == 'POST':
        # Get form data
        license_to_edit.user_id = request.form['user_id']
        license_to_edit.product_id = request.form['product_id']
        license_to_edit.license_key = request.form['license_key']
        
        expires_at = request.form.get('expires_at', None)
        if expires_at:
            license_to_edit.expires_at = datetime.strptime(expires_at, '%Y-%m-%d')
        else:
            license_to_edit.expires_at = datetime.utcnow() + timedelta(days=365)  # Default to 1 year if not set

        # Hash the updated license key
        license_to_edit.hashed_license_key = hashlib.sha256(license_to_edit.license_key.encode()).hexdigest()

        # Commit the changes to the database
        db.session.commit()

        flash('License updated successfully!')
        return redirect(url_for('admin.manage_licenses'))

    return render_template('admin/edit_license.html', license=license_to_edit, users=users, products=products)


@admin_bp.route('/delete-license/<int:license_id>', methods=['POST'], endpoint='delete_license')
@admin_required
def delete_license(license_id):
    license_to_delete = License.query.get_or_404(license_id)

    # Remove the license from the database
    db.session.delete(license_to_delete)
    db.session.commit()

    flash('License deleted successfully!')
    return redirect(url_for('admin.manage_licenses'))

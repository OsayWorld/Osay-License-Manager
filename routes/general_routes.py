from flask import Blueprint, render_template, abort, send_from_directory
from flask_login import login_required, current_user
from models.user import License, Product  # Import the Product model

general_bp = Blueprint('general', __name__)

# Discover page route (now the homepage)
@general_bp.route('/')
def discover():
    products = Product.query.all()  # Fetch all products from the database
    return render_template('discover.html', products=products)

# User dashboard route (requires login)
@general_bp.route('/dashboard')
@login_required  # Ensure that the user is logged in to access the dashboard
def dashboard():
    licenses = License.query.filter_by(user_id=current_user.id).all()
    print(f"Number of licenses found: {len(licenses)}")  # Debugging line
    return render_template('dashboard.html', licenses=licenses)


# Shop page route
@general_bp.route('/shop')
def shop():
    products = Product.query.all()  # Optionally fetch products for the shop page
    return render_template('shop.html', products=products)

# Pricing page route
@general_bp.route('/pricing')
def pricing():
    return render_template('pricing.html')

# Product details route
@general_bp.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)  # Fetch the product or return a 404
    return render_template('product_detail.html', product=product)

# Route to handle file downloads
@general_bp.route('/download/<filename>')
def download_file(filename):
    # Serve files from the 'static/uploads' folder
    return send_from_directory('static/uploads', filename, as_attachment=True)


@general_bp.route('/license/<int:license_id>')
@login_required
def view_license(license_id):
    # Fetch the license by its ID
    license = License.query.filter_by(id=license_id, user_id=current_user.id).first_or_404()
    # Optionally fetch the product details if needed
    product = license.product
    # Render the license detail page
    return render_template('view_license.html', license=license, product=product)

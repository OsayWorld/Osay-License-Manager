import hashlib
from flask import Blueprint, jsonify, request, abort, Response
from models.user import db, User, License, Product  # Ensure correct models are imported
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from flask_mail import Message # Assuming Flask-Mail is initialized in your app
import requests  # For external webhook or API calls if needed

api_bp = Blueprint('api', __name__)

# URL base to append for files hosted on external server
BASE_URL = 'https://license.osayworld.com/static/uploads/'

# Proxy route for serving files (images, APKs, scripts, etc.) through the Flask API
@api_bp.route('/file_proxy/<path:file_name>', methods=['GET'])
def proxy_file(file_name):
    # Construct the external file URL
    file_url = f'{BASE_URL}{file_name}'
    
    # Request the file from the external server
    response = requests.get(file_url, stream=True)
    
    if response.status_code == 200:
        # Return the file as a response
        mimetype = response.headers.get('Content-Type', 'application/octet-stream')
        return Response(response.content, mimetype=mimetype)
    else:
        # If the file isn't found or can't be accessed, return a 404
        abort(404)

# Route to retrieve all WordPress plugins
@api_bp.route('/plugins', methods=['GET'])
def get_plugins():
    # Query all plugins filtered by category
    products = Product.query.filter_by(category='WordPress_Plugin').all()

    # Format the product data for the response
    product_list = []
    for product in products:
        product_data = {
            'id': product.id or "No id",  # Product ID
            'title': product.name or "No title",  # Product name
            'product_type': product.product_type or "No product type",  # Product type
            'license_duration_days': product.license_duration_days or "No license duration",  # License duration
            'version': product.version or "No version",  # Current version
            'description': product.description or "No description",  # Description
            'price': product.price or "No price",  # Original price
            'effective_price': product.effective_price or "No effective price",  # Effective price considering discounts
            'is_discounted': product.is_discounted if product.is_discounted is not None else "No discount status",  # Discount status
            'discount_percentage': product.discount_percentage or "No discount percentage",  # Discount percentage
            # Prepend BASE_URL for all file fields
            'image': f'{BASE_URL}{product.image_file}' if product.image_file else "No image",
            'download_file': f'{BASE_URL}{product.download_file}' if product.download_file else "No download file",  # Download file URL
            'platform': product.platform or "No platform",  # Platform (e.g., Windows, Mac)
            'apk_file': f'{BASE_URL}{product.apk_file}' if product.apk_file else "No APK file",  # APK file URL
            'online_update_file': f'{BASE_URL}{product.online_update_file}' if product.online_update_file else "No online update file",  # Online update file URL
            'offline_update_file': f'{BASE_URL}{product.offline_update_file}' if product.offline_update_file else "No offline update file",  # Offline update file URL
            'script_file': f'{BASE_URL}{product.script_file}' if product.script_file else "No script file",  # Script file URL
            'remote_control_enabled': product.remote_control_enabled if product.remote_control_enabled is not None else "No remote control status",  # Remote control enabled status
            'remote_start_file': f'{BASE_URL}{product.remote_start_file}' if product.remote_start_file else "No remote start file",  # Remote start file URL
            'remote_stop_file': f'{BASE_URL}{product.remote_stop_file}' if product.remote_stop_file else "No remote stop file",  # Remote stop file URL
            'purchase': product.purchase if product.purchase is not None else "No purchase status",  # Purchase status
            'purchase_link': product.purchase_link or "No purchase link",  # Purchase link
            'bundle_products': product.bundle_products or "No bundle products",  # List of bundled products
            'changelog': product.changelog or "No changelog",  # Changelog
            'download_count': product.download_count or "No download count",  # Download count
            'download_limit': product.download_limit or "No download limit",  # Download limit
            'rating': product.rating or "No rating",  # Product rating
        }
        product_list.append(product_data)

    return jsonify({'status': 'success', 'products': product_list}), 200



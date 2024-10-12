from flask import Blueprint, render_template, request, redirect, url_for, flash
from extensions import db  # Import db from extensions
from models.user import License


api_bp = Blueprint('api', __name__)

@api_bp.route('/new', methods=['GET', 'POST'])
def new_api_license():
    if request.method == 'POST':
        key = request.form['key']
        product_name = request.form['product_name']
        api_key = request.form['api_key']
        usage_limit = request.form['usage_limit']
        expiry_date = request.form['expiry_date']
        
        new_license = License(
            key=key,
            product_name=product_name,
            license_type='api',
            api_key=api_key,
            usage_limit=usage_limit,
            expiry_date=expiry_date
        )
        db.session.add(new_license)
        db.session.commit()
        flash('API license added successfully!')
        return redirect(url_for('dashboard'))
    return render_template('new_api_license.html')

from flask import Blueprint, render_template, request, redirect, url_for, flash
from extensions import db  # Import db from extensions
from models.user import License
from datetime import datetime, timedelta

def assign_license_to_user(user_id, product):
    # Check if user already has a license for this product
    existing_license = License.query.filter_by(user_id=user_id, software_name=product.name).first()
    
    if existing_license:
        raise Exception(f"User already has a license for {product.name}")

    # Create new license
    new_license = License(
        software_name=product.name,
        expires_at=datetime.utcnow() + timedelta(days=product.license_duration_days),
        user_id=user_id,
        product_type=product.product_type
    )

    db.session.add(new_license)
    db.session.commit()

    return new_license



software_bp = Blueprint('software', __name__)

@software_bp.route('/new', methods=['GET', 'POST'])
def new_software_license():
    if request.method == 'POST':
        key = request.form['key']
        product_name = request.form['product_name']
        version = request.form['version']
        machine_id = request.form['machine_id']
        expiry_date = request.form['expiry_date']
        
        new_license = License(
            key=key,
            product_name=product_name,
            version=version,
            machine_id=machine_id,
            license_type='software',
            expiry_date=expiry_date
        )
        db.session.add(new_license)
        db.session.commit()
        flash('Software license added successfully!')
        return redirect(url_for('dashboard'))
    return render_template('new_software_license.html')

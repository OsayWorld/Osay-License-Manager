from flask import Blueprint, render_template, request, redirect, url_for, flash
from extensions import db  # Import db from extensions
from models.user import License

# Initialize the WordPress blueprint
wordpress_bp = Blueprint('wordpress', __name__)

# Route to create a new WordPress license
@wordpress_bp.route('/new', methods=['GET', 'POST'])
def new_wordpress_license():
    if request.method == 'POST':
        key = request.form['key']
        plugin_slug = request.form['plugin_slug']
        api_url = request.form['api_url']
        expiry_date = request.form['expiry_date']
        
        new_license = License(
            key=key,
            product_name='WordPress Plugin',
            license_type='wordpress',
            plugin_slug=plugin_slug,
            api_url=api_url,
            expiry_date=expiry_date
        )
        db.session.add(new_license)
        db.session.commit()
        flash('WordPress license added successfully!')
        return redirect(url_for('dashboard'))
    return render_template('wordpress/new_wordpress_license.html')

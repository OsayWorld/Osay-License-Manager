from routes.wordpress_routes import wordpress_bp
from routes.software_routes import software_bp
from routes.api_routes import api_bp
from routes.auth_routes import auth_bp
from routes.general_routes import general_bp
from routes.admin_routes import admin_bp  # Import the general blueprint

# Function to initialize and register blueprints
def register_blueprints(app):
    # Register each blueprint for its respective module
    app.register_blueprint(wordpress_bp, url_prefix='/wordpress')
    app.register_blueprint(software_bp, url_prefix='/software')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Register general blueprint for landing page and dashboard
    app.register_blueprint(general_bp)  # No URL prefix needed, so it handles '/' and '/dashboard'

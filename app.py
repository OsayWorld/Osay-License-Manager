from flask import Flask
from config import Config
from extensions import db, login_manager
from models.user import User  # Import the User model
from routes import register_blueprints
from flask_mail import Mail
import os

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  # Redirect to login page if not authenticated

mail = Mail(app)



# Define the user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Load the user by ID from the database

def create_app():
    # Register the blueprints
    register_blueprints(app)
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)

from extensions import db
from datetime import datetime

class Software(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(50), nullable=False, default="1.0.0")  # Version number
    description = db.Column(db.Text, nullable=False)  # General description of the software
    
    # Download links for different platforms
    download_link_windows = db.Column(db.String(255), nullable=True)
    download_link_mac = db.Column(db.String(255), nullable=True)
    download_link_linux = db.Column(db.String(255), nullable=True)

    # Licensing info
    license_required = db.Column(db.Boolean, default=True)  # Is licensing required?
    license_key = db.Column(db.String(100), unique=True, nullable=True)  # Optional license key
    license_expiry_date = db.Column(db.Date, nullable=True)  # Expiry date of the license
    
    # Cloud updates and version control
    cloud_update_url = db.Column(db.String(255), nullable=True)  # URL to check for cloud updates
    latest_version = db.Column(db.String(50), nullable=False, default="1.0.0")  # Latest available version
    release_notes = db.Column(db.Text, nullable=True)  # Release notes for the latest version
    update_available = db.Column(db.Boolean, default=False)  # Is there an update available?

    # Support information
    support_url = db.Column(db.String(255), nullable=True)  # URL to the support page
    documentation_url = db.Column(db.String(255), nullable=True)  # URL to documentation

    # Metadata and status
    active = db.Column(db.Boolean, default=True)  # Is the software active?
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # When was this software added?
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Last update timestamp

    def __repr__(self):
        return f'<Software {self.name} v{self.version}>'

"""
Configuration and Firebase initialization for Project Safehouse.
"""

import firebase_admin
from firebase_admin import credentials, firestore
import logging
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Firebase
def initialize_firebase():
    try:
        # Check if Firebase app is already initialized
        if not firebase_admin._apps:
            # Use application default credentials if available
            if os.getenv('GOOGLE_APPLICATION_CREDENTIALS'):
                cred = credentials.Certificate(os.getenv('GOOGLE_APPLICATION_CREDENTIALS'))
            else:
                # Try to use default credentials (for Google Cloud environments)
                cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
            logger.info("Firebase app initialized successfully.")
        else:
            logger.info("Firebase app already initialized.")
    except Exception as e:
        logger.error(f"Error initializing Firebase: {e}")
        raise

# Call the initialization function when this module is imported
initialize_firebase()

# Get Firestore client
def get_firestore_client():
    return firestore.client()
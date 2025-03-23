"""Test suite for the server application, validating key generation, database operations, and endpoints."""

import unittest
import datetime
import sqlite3
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from server import app, initialize_db, save_private_key_to_db, get_private_key_from_db, generate_and_store_keys


class TestApp(unittest.TestCase):
    """Test class for validating server functionality"""

    @classmethod
    def setUpClass(cls):
        """Setup for the entire test class."""
        initialize_db()

    def setUp(self):
        """Setup for each test."""
        self.client = app.test_client()  # Creates a test client
        self.app = app
        # Clear the database before each test.
        self._clear_db()

    def tearDown(self):
        """Clean up after each test."""
        self._clear_db()  # Clear the database after each test.

    def _clear_db(self):
        """Helper function to clear the database."""
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("DELETE FROM keys")  # Delete rows from the 'keys' table
        connection.commit()
        connection.close()

    def test_initialize_db(self):
        """Test if the database and table are initialized."""
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )  # Check if table exists
        result = cursor.fetchone()
        connection.close()
        self.assertIsNotNone(result)  # Assert table exists

    def test_generate_and_store_keys(self):
        """Test key generation and storage."""
        generate_and_store_keys()
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")  # Count keys in the database
        count = cursor.fetchone()[0]
        connection.close()
        self.assertGreater(count, 0)  # Assert at least one key was stored

    def test_authenticate_user(self):
        """Test the authentication endpoint."""
        generate_and_store_keys()
        payload = {"username": "testuser"}  # Sample payload with a username
        response = self.client.post('/auth', json=payload)  # Send POST to authenticate
        self.assertEqual(response.status_code, 200)  # Assert success status code
        response_data = json.loads(response.data)  # Parse response data
        self.assertIn('token', response_data)  # Assert 'token' is in response

    def test_get_jwks(self):
        """Test the /.well-known/jwks.json endpoint."""
        generate_and_store_keys()
        response = self.client.get('/.well-known/jwks.json')  # Send GET to fetch JWKS
        self.assertEqual(response.status_code, 200)  # Assert success status code
        response_data = json.loads(response.data)  # Parse response data
        self.assertIn('keys', response_data)  # Assert 'keys' in response
        self.assertGreater(len(response_data['keys']), 0)  # Assert keys exist

    def test_get_private_key_from_db(self):
        """Test private key retrieval from the database."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600  # Set expiration time
        save_private_key_to_db(private_key, exp)

        # Fetch valid key from the database.
        kid, key = get_private_key_from_db(expired=False)  # Pass False for valid keys
        self.assertIsNotNone(kid)  # Assert key ID exists
        self.assertIsNotNone(key)  # Assert key exists

    def test_get_private_key_from_db_no_valid_key(self):
        """Test retrieval when no valid key exists."""
        kid, key = get_private_key_from_db(expired=False)  # Try fetching valid key
        self.assertIsNone(kid)  # Assert no key ID
        self.assertIsNone(key)  # Assert no key

    def test_save_private_key_to_db(self):
        """Test saving a private key to the database."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600  # Set expiration time
        save_private_key_to_db(private_key, exp)

        # Verify key saved by checking count in database.
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")  # Count keys in the database
        count = cursor.fetchone()[0]
        connection.close()
        self.assertGreater(count, 0)  # Assert at least one key exists

    def test_expired_key(self):
        """Test expired key handling."""
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 3600  # Expired time
        save_private_key_to_db(expired_key, expired_time)

        # Try fetching expired key.
        kid, private_key = get_private_key_from_db(expired=True)  # Fetch expired key
        self.assertIsNotNone(kid)  # Assert expired key ID exists
        self.assertIsNotNone(private_key)  # Assert expired key exists

    def test_jwks_with_expired_keys(self):
        """Test if expired keys appear in the JWKS endpoint."""
        generate_and_store_keys()
        response = self.client.get('/.well-known/jwks.json?expired=true')  # Request expired keys
        self.assertEqual(response.status_code, 200)  # Assert success status code
        response_data = json.loads(response.data)  # Parse response data
        self.assertGreater(len(response_data['keys']), 0)  # Assert keys, including expired

if __name__ == '__main__':
    unittest.main()  # Run the tests





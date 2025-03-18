import unittest
import sqlite3
import json
from server import app, initialize_db, save_private_key_to_db, get_private_key_from_db, generate_and_store_keys
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime


class TestApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Setup for the entire test class. Initializes the database and app."""
        initialize_db()

    def setUp(self):
        """Setup for each individual test."""
        self.client = app.test_client()  # Creates a test client for sending requests to the app
        self.app = app
        # Clear the database before each test to avoid interference.
        self._clear_db()

    def tearDown(self):
        """Clean up after each test."""
        self._clear_db()  # Clear the database after each test to ensure no state persists across tests.

    def _clear_db(self):
        """Helper function to clear the database."""
        # Connect to the SQLite database and delete all rows from the 'keys' table.
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("DELETE FROM keys")
        connection.commit()
        connection.close()

    def test_initialize_db(self):
        """Test if the database and table are properly initialized."""
        # Check if the 'keys' table exists in the database after initialization.
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")  # Query to check if the table exists
        result = cursor.fetchone()
        connection.close()
        self.assertIsNotNone(result)  # Assert that the table was created successfully (i.e., result is not None)

    def test_generate_and_store_keys(self):
        """Test the key generation and storage in the database."""
        # Generate keys and store them in the database.
        generate_and_store_keys()
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")  # Count how many keys are in the database
        count = cursor.fetchone()[0]
        connection.close()
        self.assertGreater(count, 0)  # Assert that at least one key was stored in the database

    def test_authenticate_user(self):
        """Test the authentication endpoint."""
        # Generate keys and attempt to authenticate a user.
        generate_and_store_keys()
        payload = {"username": "testuser"}  # Sample payload with a username
        response = self.client.post('/auth', json=payload)  # Send POST request to authenticate the user
        self.assertEqual(response.status_code, 200)  # Assert that the status code is 200 (success)
        response_data = json.loads(response.data)  # Parse the response data
        self.assertIn('token', response_data)  # Assert that the response contains a 'token'

    def test_get_jwks(self):
        """Test the /.well-known/jwks.json endpoint."""
        # Generate keys and test the JWKS endpoint for the public keys.
        generate_and_store_keys()
        response = self.client.get('/.well-known/jwks.json')  # Send GET request to fetch the JWKS
        self.assertEqual(response.status_code, 200)  # Assert that the status code is 200
        response_data = json.loads(response.data)  # Parse the response data
        self.assertIn('keys', response_data)  # Assert that the response contains 'keys'
        self.assertGreater(len(response_data['keys']), 0)  # Assert that there is at least one key in the response

    def test_get_private_key_from_db(self):
        """Test the retrieval of private keys from the database."""
        # Insert a valid key into the database.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600  # Set expiration time in the future
        save_private_key_to_db(private_key, exp)

        # Fetch the valid key from the database.
        kid, key = get_private_key_from_db(expired=False)  # Pass False to fetch a valid key
        self.assertIsNotNone(kid)  # Assert that the key ID is not None
        self.assertIsNotNone(key)  # Assert that the key is not None

    def test_get_private_key_from_db_no_valid_key(self):
        """Test retrieval of private key when no valid key exists."""
        # Try to fetch a private key when no valid key exists (should return None).
        kid, key = get_private_key_from_db(expired=False)
        self.assertIsNone(kid)  # Assert that no key ID is returned
        self.assertIsNone(key)  # Assert that no key is returned

    def test_save_private_key_to_db(self):
        """Test saving a private key to the database."""
        # Generate and save a private key to the database.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600  # Set expiration time
        save_private_key_to_db(private_key, exp)

        # Verify that the key was saved successfully by checking the database count.
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")  # Count the number of keys in the database
        count = cursor.fetchone()[0]
        connection.close()
        self.assertGreater(count, 0)  # Assert that there is at least one key in the database

    def test_expired_key(self):
        """Test that expired keys are properly handled."""
        # Generate and insert an expired key.
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 3600  # Set expiration time in the past
        save_private_key_to_db(expired_key, expired_time)

        # Try to fetch an expired key.
        kid, private_key = get_private_key_from_db(expired=True)  # Pass True to fetch expired keys
        self.assertIsNotNone(kid)  # Assert that the expired key's ID is returned
        self.assertIsNotNone(private_key)  # Assert that the expired key itself is returned

    def test_jwks_with_expired_keys(self):
        """Test if expired keys appear in the JWKS endpoint if specified."""
        # Generate keys, including expired ones, and test the JWKS endpoint for expired keys.
        generate_and_store_keys()
        response = self.client.get('/.well-known/jwks.json?expired=true')  # Request expired keys
        self.assertEqual(response.status_code, 200)  # Assert that the status code is 200
        response_data = json.loads(response.data)  # Parse the response data
        self.assertGreater(len(response_data['keys']), 0)  # Assert that there is at least one key in the response, including expired ones


if __name__ == '__main__':
    unittest.main()  # Run the tests


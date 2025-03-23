"""
This module implements JWT-based authentication using RSA keys stored in an SQLite database.
It exposes two routes:
1. /auth - Accepts a POST request to authenticate users and return a signed JWT token.
2. /.well-known/jwks.json - Returns the public keys in JSON Web Key Set (JWKS) format.
"""

import base64
import sqlite3
import datetime
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify

app = Flask(__name__)

def initialize_db():
    """
    Initializes the SQLite database, creating the 'keys' table if it doesn't already exist.
    """
    connection = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    connection.commit()
    connection.close()

def save_private_key_to_db(private_key, exp):
    """
    Saves a private key into the database with an expiration time.
    """
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    connection = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = connection.cursor()
    cursor.execute('''
        INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (pem_key, exp))
    connection.commit()
    connection.close()

def get_private_key_from_db(expired=False):
    """
    Retrieves a private key from the database, either expired or not.
    """
    connection = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = connection.cursor()
    current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if expired:
        cursor.execute('''
            SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1
        ''', (current_time,))
    else:
        cursor.execute('''
            SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1
        ''', (current_time,))
    key_row = cursor.fetchone()
    connection.close()
    if key_row:
        private_key = serialization.load_pem_private_key(key_row[1], password=None)
        return key_row[0], private_key
    return None, None

def generate_and_store_keys():
    """
    Generates two RSA keys, one valid and one expired, and stores them in the database.
    """
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    save_private_key_to_db(valid_key,int(datetime.datetime.now(datetime.timezone.utc).timestamp())
                           +3600)
    save_private_key_to_db(expired_key,int(datetime.datetime.now(datetime.timezone.utc).timestamp())
                           -3600)

@app.route('/auth', methods=['POST'])
def authenticate_user():
    """
    Authenticates a user by generating a JWT using a private key from the database.
    """
    request_data = request.get_json()
    include_expired_token = request.args.get('expired', 'false').lower() == 'true'
    kid, private_key = get_private_key_from_db(expired=include_expired_token)
    if not private_key:
        return jsonify({'message': 'No appropriate key available'}), 404
    token_payload = {
        'sub': request_data['username'],
        'iat': datetime.datetime.now(datetime.timezone.utc),
        'exp': (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
        ) if not include_expired_token else (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30)
        )
    }
    token = jwt.encode(token_payload, private_key, algorithm='RS256', headers={'kid': str(kid)})
    return jsonify({'token': token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    """
    Returns the public keys in JWKS format.
    """
    keys = []
    connection = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = connection.cursor()
    cursor.execute('''
        SELECT kid, key FROM keys WHERE exp > ?
    ''', (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
    for row in cursor.fetchall():
        kid = row[0]
        private_key = serialization.load_pem_private_key(row[1], password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        n_base64 = base64.urlsafe_b64encode(public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
        e_base64 = base64.urlsafe_b64encode(public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
        jwk = {
            'kid': str(kid),
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'n': n_base64,
            'e': e_base64,
        }
        keys.append(jwk)
    connection.close()
    return jsonify({'keys': keys})

if __name__ == '__main__':
    initialize_db()
    generate_and_store_keys()
    app.run(port=8080, debug=True)
































import sqlite3
import datetime
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify

app = Flask(__name__)

# SQLite database setup
def initialize_db():
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

# Save private key to the database
def save_private_key_to_db(private_key, exp):
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

# Fetch a private key from the database (valid or expired)
def get_private_key_from_db(expired=False):
    connection = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = connection.cursor()
    
    current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())  # Updated line
    
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
        return key_row[0], private_key  # return kid and key
    return None, None

# Generate and store keys in the database
def generate_and_store_keys():
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Store the valid key (expires in 1 hour)
    save_private_key_to_db(valid_key, int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600)  # Updated line
    
    # Store the expired key (expired 1 hour ago)
    save_private_key_to_db(expired_key, int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 3600)  # Updated line

# POST /auth endpoint for issuing JWT tokens
@app.route('/auth', methods=['POST'])
def authenticate_user():
    request_data = request.get_json()
    include_expired_token = request.args.get('expired', 'false').lower() == 'true'

    kid, private_key = get_private_key_from_db(expired=include_expired_token)
    
    if not private_key:
        return jsonify({'message': 'No appropriate key available'}), 404
    
    token_payload = {
        'sub': request_data['username'],
        'iat': datetime.datetime.now(datetime.timezone.utc),  # Updated line
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30) if not include_expired_token else datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30)  # Updated line
    }

    token = jwt.encode(token_payload, private_key, algorithm='RS256', headers={'kid': str(kid)})
    
    return jsonify({'token': token})

# GET /.well-known/jwks.json endpoint to get public keys
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    keys = []
    connection = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = connection.cursor()
    cursor.execute(''' 
        SELECT kid, key FROM keys WHERE exp > ?
    ''', (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))  # Updated line

    for row in cursor.fetchall():
        kid = row[0]
        private_key = serialization.load_pem_private_key(row[1], password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        n_base64 = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
        e_base64 = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")

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
    generate_and_store_keys()  # Generate and insert keys into DB
    app.run(port=8080, debug=True)































# Extending the Basic JWKS Server
![Python Version](https://img.shields.io/badge/python-blue)

---

## **Overview**  
This project extends the basic JWKS (JSON Web Key Set) server by integrating SQLite for persistent key storage. This enhancement ensures that private keys remain available even if the server is restarted or moved. The implementation also focuses on preventing SQL injection attacks and improving security by enforcing proper database interactions.  
By utilizing SQLite, the JWKS server now supports:  
- Secure storage and retrieval of RSA private keys.  
- Proper key expiration handling.  
- JWT issuance using keys stored in a database.  
- Resilience against SQL injection.

---

## 📌 Requirements  
✅ Store RSA key pairs in a SQLite database (`totally_not_my_privateKeys.db`).  
✅ Ensure private keys are persisted and remain available across server restarts.  
✅ Secure database interactions to prevent SQL injection attacks.  
✅ Modify `/auth` and `/jwks` endpoints to use the database for key management.  
✅ Implement a test suite with over 80% coverage.  
✅ Ensure compatibility with black-box testing.

---

## **📌 Endpoints**

| **Method** | **Endpoint**             | **Description**                           |  
| ---------- | ------------------------ | ----------------------------------------- |  
| `GET`      | `/.well-known/jwks.json` | Returns active public keys in JWKS format |  
| `POST`     | `/auth`                  | Returns a signed JWT                      |  
| `POST`     | `/auth?expired=true`     | Returns a JWT signed with an expired key  |

---

## **🚀 Installation & Setup**

### **Prerequisites**  
- Python (Ensure you have Python installed)  
- Flask (Web framework)  
- PyJWT (JWT Library)  
- SQLite (Database)

### **1️⃣ Clone the Repository**  
```bash  
git clone https://github.com/NiallJC/Extending-my-JWKS-server.git  
cd Extending-my-JWKS-server
```

### **2️⃣ Install dependencies**  
```bash  
pip install -r requirements.txt  
```

### **3️⃣ Initialize the Database & Run the Server**  
```bash  
python server.py  
```

### **4️⃣ Run Tests**  
```bash  
python -m pytest --cov=server --cov-report=term server_test_suite.py 
```

---

## **🛠 How It Works**

### **Database Integration**  
- The server creates and manages an SQLite database (`totally_not_my_privateKeys.db`).  
- Keys are stored with unique `kid` values and expiration timestamps.  
- Expired keys are not served by the JWKS endpoint.

### **JWT Signing Process**  
- The `/auth` endpoint retrieves a valid key from the database to sign a JWT.  
- If `expired=true` is provided, an expired key is used.  
- JWTs contain standard claims such as `sub`, `iat`, and `exp`.

### **Security Measures**  
- SQL queries use parameterized statements to prevent injection attacks.  
- Database connections are securely handled and closed after each transaction.  
- JWTs are signed with RSA keys using the RS256 algorithm.

---

## ✅ Example Requests & Responses

### **Retrieve JWKS**

#### Request:  
```bash  
curl http://127.0.0.1:8080/.well-known/jwks.json  
```

#### Response:  
```json  
{  
  "keys": [  
    {  
      "alg": "RS256",  
      "e": "AQAB",  
      "kid": "1",  
      "kty": "RSA",  
      "n": "vhdL0XQ0Bw5BbJm2YPXL...",  
      "use": "sig"  
    }  
  ]  
}  
```

### **Issue a JWT**

#### Request:  
```bash  
curl -X POST http://127.0.0.1:8080/auth -H "Content-Type: application/json" -d '{"username": "userABC"}'  
```

#### Response:  
```json  
{  
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ..."  
}  
```

---

## 📸 Screenshots  
- 📌 Test Client Output  
- 📌 Test Suite Coverage Report  
Screenshots are included in the repository.

---

## ⭐ Future Improvements  
- Implement full user authentication.  
- Secure key storage (e.g., hardware security modules or encrypted storage).  
- Add logging and monitoring for security events.  
- Implement rate limiting to mitigate abuse.

---


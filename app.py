from flask import Flask, request, jsonify
import joblib
import numpy as np
import sqlite3
import jwt
import datetime
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'my_jwt_secret_for_my_app'  # Change this to a strong secret key

# Load the model and feature names
model = joblib.load('covid_prediction_model.joblib')
feature_names = joblib.load('feature_names.joblib')

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,Aadhar TEXT UNIQUE NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# JWT Token Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            token = token.split(" ")[1]  # Remove 'Bearer' from token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Signup API
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('Name')
    password = data.get('password')
    email=data.get('email')
    aadhar=data.get('aadharId')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email,username, password,Aadhar) VALUES (?, ?,?,?)", (email,username, hashed_password,aadhar))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400

# Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('email')
    password = data.get('password')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE email=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[0], password):
        token = jwt.encode(
            {'email': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Protected API (Example)
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({'message': f'Hello {current_user}, you have access to this route!'})

# Predict API (Requires JWT Token)
@app.route('/predict', methods=['POST'])
@token_required
def predict_covid(current_user):
    try:
        data = request.json

        if not isinstance(data, list):
            return jsonify({'error': 'Input must be a list of binary values', 'expected_length': len(feature_names)}), 400
        
        if len(data) != len(feature_names):
            return jsonify({'error': 'Input length mismatch', 'expected_length': len(feature_names), 'received_length': len(data)}), 400

        if not all(value in [0, 1] for value in data):
            return jsonify({'error': 'Input must contain only 0 or 1 values'}), 400

        input_data = np.array(data).reshape(1, -1)
        prediction = model.predict(input_data)
        prediction_proba = model.predict_proba(input_data)

        return jsonify({
            'prediction': int(prediction[0]),
            'probability': {
                'negative': float(prediction_proba[0][0]),
                'positive': float(prediction_proba[0][1])
            },
            'interpretation': 'Prediction of 1 indicates potential COVID-19 infection, 0 indicates no infection',
            'features': feature_names
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Feature List API
@app.route('/features', methods=['GET'])
def get_features():
    return jsonify({'features': feature_names, 'total_features': len(feature_names)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)

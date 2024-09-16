import jwt
import time
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def read_private_key(file_path, password=None):
    """Read private key from file"""
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    return private_key

def read_public_key(file_path):
    """Read public key from file"""
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def generate_jwt_token(payload, private_key, algorithm="RS512"):
    """Generate JWT token using RSA private key"""
    jwt_token = jwt.encode(payload, private_key, algorithm=algorithm)
    return jwt_token

def print_keys(private_key, public_key):
    """Print public and private keys"""
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Public Key:")
    print(public_key_pem.decode("utf-8"))
    print("Private Key:")
    print(private_key_pem.decode("utf-8"))

def read_config(file_path):
    """Read configuration from JSON file"""
    with open(file_path, 'r') as config_file:
        config = json.load(config_file)
    return config

# Paths to your key files and configuration file
private_key_file = "private_key.pem"
public_key_file = "public_key.pem"
config_file = "config.json"

# Read the private and public keys from files
private_key = read_private_key(private_key_file)
public_key = read_public_key(public_key_file)

# Print public and private keys
print_keys(private_key, public_key)

# Read configuration from JSON file
config = read_config(config_file)

# Generate current Unix timestamp
int_time = int(time.time())
exp_time = int_time + config.get('exp_offset', 3600)  # Default to 3600 seconds (1 hour) if not in config

# Generate JWT token with payload from configuration
payload = {
    "iss": config.get('iss', 'default_issuer'),
    "iat": int_time + config.get('iat_offset', 0),  # Default to 0 if not in config
    "exp": exp_time,
    "name": config.get('name', 'default_name'),   # Additional field 'aud'
    "sub": config.get('sub', 'default_subject')     # Additional field 'sub'
}

jwt_token = generate_jwt_token(payload, private_key)

print("JWT Token:")
print(jwt_token)

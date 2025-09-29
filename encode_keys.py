#!/usr/bin/env python3
"""
Ed25519 Key Generator and Base64 Encoder for MatrixRTC Authorization Service
"""

import base64
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def generate_keypair():
    """Generate new Ed25519 keypair"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def encode_private_key(private_key):
    """Encode private key to base64"""
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(private_bytes).decode('utf-8')

def encode_public_key(public_key):
    """Encode public key to base64"""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(public_bytes).decode('utf-8')

def encode_from_file(filepath):
    """Encode key from PEM file"""
    try:
        with open(filepath, 'rb') as f:
            key_data = f.read()
        
        # Try to load as private key first
        try:
            private_key = serialization.load_pem_private_key(key_data, password=None)
            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                return encode_private_key(private_key)
        except:
            pass
        
        # Try to load as public key
        try:
            public_key = serialization.load_pem_public_key(key_data)
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                return encode_public_key(public_key)
        except:
            pass
        
        print(f"Error: {filepath} is not a valid Ed25519 key file")
        return None
    except FileNotFoundError:
        print(f"Error: File {filepath} not found")
        return None

def main():
    if len(sys.argv) == 1:
        # Generate new keypair
        print("Generating new Ed25519 keypair...")
        private_key, public_key = generate_keypair()
        
        private_b64 = encode_private_key(private_key)
        public_b64 = encode_public_key(public_key)
        
        print("\n Generated Keys (Base64 encoded):")
        print(f"MATRIX_PRIVATE_KEY={private_b64}")
        print(f"SYNAPSE_PUBLIC_KEY={public_b64}")
        
        print("\n Environment Variables:")
        print(f'export MATRIX_PRIVATE_KEY="{private_b64}"')
        print(f'export SYNAPSE_PUBLIC_KEY="{public_b64}"')
        
    elif len(sys.argv) == 2:
        # Encode existing key file
        filepath = sys.argv[1]
        encoded = encode_from_file(filepath)
        if encoded:
            print(f"Base64 encoded key: {encoded}")
    else:
        print("Usage:")
        print("  python3 encode_keys.py                 # Generate new keypair")
        print("  python3 encode_keys.py <key_file.pem>  # Encode existing key")

if __name__ == "__main__":
    main()

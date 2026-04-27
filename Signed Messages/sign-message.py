import sys

import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers, rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1
)

from cryptography.hazmat.primitives import hashes, serialization
from sympy import nextprime

def prime_derivation_1(seed):

    print("[DEBUG] Prime derivation step 1:\n"+
          "[DEBUG] Converting SHA256(seed) into a large integer")
    
    seed_bytes = bytes(seed)
    seed_sha_hash = hashlib.sha256(seed_bytes)
    seed_large_integer = int.from_bytes(seed_sha_hash.digest(), byteorder="big")

    print("[DEBUG] Checking consecutive integers until a valid prime is reached")
    return nextprime(seed_large_integer)

def prime_derivation_2(seed):

    print('\n[DEBUG] Prime derivation step 2:')
    print('[DEBUG] Modifying seed with PKI-related constant (SHA256(seed + b"pki"))')
    modified_seed = seed + b"pki"

    print('[DEBUG] Hashing modified seed with SHA256')
    modified_seed_hash = hashlib.sha256(modified_seed)

    print('[DEBUG] Converting hash into a large integer')
    seed_large_integer = int.from_bytes(modified_seed_hash.digest(), byteorder="big")

    print('[DEBUG] Checking consecutive integers until a valid prime is reached')
    return nextprime(seed_large_integer)


def create_private_key(p, q):
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))

    dp    = rsa_crt_dmp1(d, p)
    dq    = rsa_crt_dmq1(d, q)
    iqmp  = rsa_crt_iqmp(p, q)
    
    public_numbers = RSAPublicNumbers(e, n)
    private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, iqmp, public_numbers)
    private_key = private_numbers.private_key()

    return private_key

def create_key_pair(username, private_key):

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8,            
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{username.decode()}-private.pem", "w") as out:
        out.write(private_pem.decode())

    with open(f"{username.decode()}-public.pem", "w") as out:
        out.write(public_pem.decode())


def sign_message(private_key, message):

    signature = private_key.sign(message,
                                 padding.PSS(
                                     mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH
                                 ),
                                 hashes.SHA256()
                                 ).hex()
    
    return signature
    



def main(username, message):
    seed = username + b"_lovenote_2026_valentine"

    p = prime_derivation_1(seed)
    print(f'[DEBUG] Prime p selected: {p}')

    q = prime_derivation_2(seed)
    print(f'[DEBUG] Prime q selected: {q}')

    private_key = create_private_key(p, q)
    create_key_pair(username, private_key)

    print('\n[SUCCESS] RSA modulus generated from p × q'+
          '\n[SUCCESS] RSA-2048 key pair successfully constructed'+
          '\n[SUCCESS] Public and private keys saved to disk')
    
    signature = sign_message(private_key, message)

    print(f"\n[HACKER] Signature for user's message: {signature}")




if __name__ == "__main__":
    if len(sys.argv) == 3:
        username = bytes(sys.argv[1:][0], "UTF-8")
        message = bytes(sys.argv[1:][1], "UTF-8")

        main(username, message)
    else:
        print("Usage: sign-message.py [username] [message]")
    


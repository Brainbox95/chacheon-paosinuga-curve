import os
import json
import base64
import uuid
import logging
import time
import hashlib
import random
import sympy
import psutil
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# AWS Configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1') #replace with your Region
S3_BUCKET_NAME = 'Replace with your bucket name'
KMS_KEY_ID = 'replace with your KMS'
def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if sympy.isprime(p):
            return p

class EllipticCurve:
    def __init__(self, bits):
        self.p = generate_prime(bits)
        self.a = random.randint(1, self.p - 1)
        self.b = random.randint(1, self.p - 1)
        self.G = self.generate_base_point()
        self.n = self.calculate_order()

    def generate_base_point(self):
        while True:
            x = random.randint(1, self.p - 1)
            y_squared = (x**3 + self.a * x + self.b) % self.p
            if sympy.legendre_symbol(y_squared, self.p) == 1:
                y = pow(y_squared, (self.p + 1) // 4, self.p)
                return (x, y)

    def calculate_order(self):
        return generate_prime(self.p.bit_length())

    def add_points(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and P[1] != Q[1]:
            return None
        if P != Q:
            lam = ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p)) % self.p
        else:
            lam = ((3 * P[0]**2 + self.a) * pow(2 * P[1], -1, self.p)) % self.p
        x3 = (lam**2 - P[0] - Q[0]) % self.p
        y3 = (lam * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)

    def scalar_mult(self, k, P):
        R = None
        for i in range(256):
            if (k >> i) & 1:
                R = self.add_points(R, P)
            P = self.add_points(P, P)
        return R

class ChaCheongIBS:
    def __init__(self, bits=256):
        self.curve = EllipticCurve(bits)
        self.master_key = self.generate_master_key()

    def generate_master_key(self):
        return random.randint(1, self.curve.n - 1)

    def extract_private_key(self, identity):
        h = int.from_bytes(hashlib.sha256(identity.encode()).digest(), 'big')
        return (self.master_key * h) % self.curve.n

    def sign(self, private_key, message):
        k = random.randint(1, self.curve.n - 1)
        R = self.curve.scalar_mult(k, self.curve.G)
        r = R[0] % self.curve.n
        h = int.from_bytes(hashlib.sha256(message.encode() + str(r).encode()).digest(), 'big')
        s = (k + private_key * h) % self.curve.n
        return (r, s)

    def verify(self, public_key, message, signature):
        r, s = signature
        h = int.from_bytes(hashlib.sha256(message.encode() + str(r).encode()).digest(), 'big')
        w = pow(s, -1, self.curve.n)
        u1 = (h * w) % self.curve.n
        u2 = (r * w) % self.curve.n
        X = self.curve.add_points(
            self.curve.scalar_mult(u1, self.curve.G),
            self.curve.scalar_mult(u2, public_key)
        )
        if X is None:
            return False
        return r == X[0] % self.curve.n

class ThresholdSecretSharing:
    def __init__(self, threshold, total_shares):
        self.threshold = threshold
        self.total_shares = total_shares

    def generate_shares(self, secret):
        coefficients = [secret] + [random.randint(0, 2**256) for _ in range(self.threshold - 1)]
        shares = []
        for i in range(1, self.total_shares + 1):
            share = sum(c * pow(i, j, 2**256) for j, c in enumerate(coefficients)) % 2**256
            shares.append((i, share))
        return shares

    def reconstruct_secret(self, shares):
        def lagrange_interpolation(x, x_s, y_s):
            def pi(vals):
                acc = 1
                for v in vals:
                    acc *= v
                return acc
            nums = []
            dens = []
            for i, x_i in enumerate(x_s):
                others = list(x_s[:i]) + list(x_s[i+1:])
                nums.append(pi(x - o for o in others))
                dens.append(pi(x_i - o for o in others))
            den = pi(dens)
            num = sum([nums[i] * den * y_i * pow(dens[i], -1, 2**256) for i, y_i in enumerate(y_s)])
            return (num * pow(den, -1, 2**256)) % 2**256

        return lagrange_interpolation(0, [s[0] for s in shares], [s[1] for s in shares])

def performance_monitor(func):
    def wrapper(*args, **kwargs):
        process = psutil.Process()
        start_time = time.time()
        start_memory = process.memory_info().rss / 1024 / 1024  # Memory in MB
        
        result = func(*args, **kwargs)
        
        end_time = time.time()
        end_memory = process.memory_info().rss / 1024 / 1024  # Memory in MB
        
        logger.info(f"{func.__name__} performance:")
        logger.info(f"  Runtime: {end_time - start_time:.4f} seconds")
        logger.info(f"  Memory usage: {end_memory - start_memory:.2f} MB")
        
        return result
    return wrapper

class SecureCloudTransfer:
    def __init__(self):
        self.chacheon = ChaCheongIBS()
        self.users = {}
        self.s3_client = boto3.client('s3', region_name=AWS_REGION)
        self.bucket_name = S3_BUCKET_NAME
        self.tss = ThresholdSecretSharing(threshold=3, total_shares=5)

    @performance_monitor
    def register_user(self, username, password):
        """Register a user with username and password."""
        chacheon_private_key = self.chacheon.extract_private_key(username)
        chacheon_public_key = self.chacheon.curve.scalar_mult(chacheon_private_key, self.chacheon.curve.G)
        
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
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

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            'chacheon_private_key': chacheon_private_key,
            'chacheon_public_key': chacheon_public_key,
            'ec_private_key': private_pem,
            'ec_public_key': public_pem,
            'password_hash': password_hash
        }
        logger.info(f"User {username} registered successfully.")
        
        confirmation = input(f"Confirm registration for {username} (yes/no): ").strip().lower()
        if confirmation != 'yes':
            logger.error("Registration not confirmed.")
            del self.users[username]  # Remove user if confirmation fails
            return
        logger.info(f"User {username} registered and confirmed successfully.")

    @performance_monitor
    def send_message(self, sender, recipient, message):
        """Send an encrypted message from sender to recipient."""
        if sender not in self.users:
            logger.error("Sender not found.")
            return
        
        if recipient not in self.users:
            logger.error("Recipient not found.")
            return

        password = input(f"Enter password for user {sender}: ")
        user_data = self.users.get(sender)
        if hashlib.sha256(password.encode()).hexdigest() != user_data['password_hash']:
            logger.error("Authentication failed.")
            return
        
        logger.info("User authenticated successfully.")

        key = os.urandom(32)  # 256-bit key for AES
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        tag = encryptor.tag
        
        message_id = str(uuid.uuid4())
        s3_key = f"messages/{recipient}/{message_id}"  # Store under recipient's path
        s3_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'key': base64.b64encode(key).decode()  # Store key in base64 format
        }

        logger.info(f"Storing message with key: {s3_key} in bucket: {self.bucket_name}")

        try:
            self.s3_client.put_object(Bucket=self.bucket_name, Key=s3_key, Body=json.dumps(s3_data))
            logger.info(f"Message sent successfully with ID {message_id}.")
        except ClientError as e:
            logger.error("Error accessing S3 bucket.")
            logger.error(e)
        
        return message_id

    @performance_monitor
    def receive_message(self, recipient, message_id):
        """Receive and decrypt a message for the recipient."""
        if recipient not in self.users:
            logger.error("Recipient not found.")
            return
        
        s3_key = f"messages/{recipient}/{message_id}"
        logger.info(f"Retrieving message from S3 key: {s3_key} in bucket: {self.bucket_name}")

        try:
            message_object = self.s3_client.get_object(Bucket=self.bucket_name, Key=s3_key)
            s3_data = json.loads(message_object['Body'].read().decode())
            ciphertext = base64.b64decode(s3_data['ciphertext'])
            tag = base64.b64decode(s3_data['tag'])
            nonce = base64.b64decode(s3_data['nonce'])
            key = base64.b64decode(s3_data['key'])

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                logger.info(f"Message received successfully: {plaintext.decode()}")
            except Exception as e:
                logger.error("Error decrypting message.")
                logger.error(e)
        except ClientError as e:
            logger.error("Error accessing S3 bucket.")
            logger.error(e)
    
    def store_message(self, sender, recipient, message):
        """Store message to S3 after encrypting it."""
        # This function can be used to refactor the send_message for more specific storing operation.
        pass

    def retrieve_message(self, recipient, message_id):
        """Retrieve and decrypt the stored message from S3."""
        # This function can be used to refactor the receive_message for more specific retrieving operation.
        pass

#  usage
transfer_system = SecureCloudTransfer()
transfer_system.register_user('Paul9008', 'oi$WRTT%5577GG')
transfer_system.register_user('Samba56', '776%%%gbbjkskk001')

#  send and receive a message
message_id = transfer_system.send_message('Paul9008', 'Samba56', 'I am a blank page waiting for life to start, paint me a heart, let me be your Art!')
transfer_system.receive_message('Samba56', message_id)

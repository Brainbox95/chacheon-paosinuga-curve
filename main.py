import os
import base64
import json
import uuid
import logging
import boto3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from chacheon_ibs import ChaCheongIBS

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# AWS Configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
S3_BUCKET_NAME = 'bimbi2'
KMS_KEY_ID = '325b7e1b-5346-44ba-9349-f9bcced77447'

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

class SecureCloudTransfer:
    def __init__(self):
        self.chacheon = ChaCheongIBS()
        self.users = {}
        self.s3_client = boto3.client('s3', region_name=AWS_REGION)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.bucket_name = S3_BUCKET_NAME
        self.kms_key_id = KMS_KEY_ID
        self.tss = ThresholdSecretSharing(threshold=3, total_shares=5)

    def register_user(self, username, password):
        chacheon_private_key = self.chacheon.extract_private_key(username)
        chacheon_public_key = self.chacheon.curve.scalar_mult(chacheon_private_key, self.chacheon.G)
        
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

    def authenticate_user(self, username, password):
        if username not in self.users:
            logger.error(f"User {username} does not exist.")
            return False

        user = self.users[username]
        if hashlib.sha256(password.encode()).hexdigest() != user['password_hash']:
            logger.error("Password is incorrect.")
            return False

        logger.info(f"User {username} authenticated successfully.")
        return True

    def upload_file(self, username, file_path):
        if username not in self.users:
            logger.error(f"User {username} does not exist.")
            return

        file_name = os.path.basename(file_path)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = self.encrypt_data(file_data)
        self.s3_client.put_object(Bucket=self.bucket_name, Key=file_name, Body=encrypted_data)
        logger.info(f"File {file_name} uploaded successfully to bucket {self.bucket_name}.")

    def download_file(self, username, file_name, download_path):
        if username not in self.users:
            logger.error(f"User {username} does not exist.")
            return

        response = self.s3_client.get_object(Bucket=self.bucket_name, Key=file_name)
        encrypted_data = response['Body'].read()
        file_data = self.decrypt_data(encrypted_data)

        with open(download_path, 'wb') as file:
            file.write(file_data)
        logger.info(f"File {file_name} downloaded successfully to {download_path}.")

    def encrypt_data(self, data):
        key_id = self.kms_key_id
        encryption_context = {'Purpose': 'FileEncryption'}
        response = self.kms_client.generate_data_key(KeyId=key_id, KeySpec='AES_256')
        plaintext_key = response['Plaintext']
        ciphertext_key = response['CiphertextBlob']

        cipher = Cipher(algorithms.AES(plaintext_key), modes.GCM())
        encryptor = cipher.encryptor()
        ciphertext, tag = encryptor.update(data) + encryptor.finalize()
        
        encrypted_data = ciphertext_key + cipher.nonce + tag + ciphertext
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        key_id = self.kms_key_id
        ciphertext_key, nonce, tag, ciphertext = encrypted_data[:64], encrypted_data[64:80], encrypted_data[80:96], encrypted_data[96:]

        response = self.kms_client.decrypt(CiphertextBlob=ciphertext_key)
        plaintext_key = response['Plaintext']

        cipher = Cipher(algorithms.AES(plaintext_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data

if __name__ == "__main__":
    secure_transfer = SecureCloudTransfer()
    secure_transfer.register_user('alice', 'securepassword')
    secure_transfer.authenticate_user('alice', 'securepassword')

    file_path = 'path/to/your/file.txt'
    secure_transfer.upload_file('alice', file_path)
    secure_transfer.download_file('alice', 'file.txt', 'path/to/download/file.txt')

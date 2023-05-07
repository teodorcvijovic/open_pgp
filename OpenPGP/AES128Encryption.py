from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from EncryptionAlgorithm import EncryptionAlgorithm
from Message import Message
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets


class AES128Encryption(EncryptionAlgorithm):

    def generate_session_key(self):
        key = secrets.token_bytes(16)
        return key

    def encrypt(self, message: Message, recipient_public_key_id):
        session_key = self.generate_session_key()

        algorithm = algorithms.AES(session_key)

        data = message.get_data_for_encryption().encode('utf-8')

        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = b'0123456776543210'
        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # encrypted session key
        encrypted_session_key = self.encrypt_session_key(session_key, recipient_public_key_id)

        return encrypted_data, encrypted_session_key

    def decrypt(self, message, my_public_key_id, passphrase):
        session_key = self.decrypt_encrypted_session_key(message.encrypted_session_key, my_public_key_id, passphrase)
        encrypted_data = message.encrypted_data

        algorithm = algorithms.AES(session_key)

        iv = b'0123456776543210'
        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8')
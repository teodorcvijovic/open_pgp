from abc import abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from asymmetric_encryption.PrivateKeyRing import privateKeyRing
from asymmetric_encryption.PublicKeyRing import publicKeyRing
from asymmetric_encryption.AsymmetricEncryption import AsymmetricEncryption

class EncryptionAlgorithm:

    @abstractmethod
    def algorithm_code(self):
        pass

    @abstractmethod
    def generate_session_key(self):
        pass

    @abstractmethod
    def generate_initial_value(self):
        pass

    @abstractmethod
    def get_algorithm(self, session_key):
        pass

    # template method
    def encrypt(self, message_string, recipient_public_key_id):
        # prepare input
        session_key = self.generate_session_key()
        # message_bytes = message_string.encode('utf-8')
        message_bytes = message_string
        algorithm = self.get_algorithm(session_key)

        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()

        # encrypt data
        iv = self.generate_initial_value()
        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # encrypted session key with recipient's public key
        encrypted_session_key = self.encrypt_session_key(session_key, recipient_public_key_id)

        return encrypted_data, encrypted_session_key

    # template method
    def decrypt(self, session_key, encrypted_data):
        algorithm = self.get_algorithm(session_key)

        # decrypt data with decrypted session key
        iv = self.generate_initial_value()
        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        unpadded_data_bytes = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data_bytes.decode('utf-8')

    def encrypt_session_key(self, session_key, recipient_public_key_id):
        public_key = publicKeyRing.get_key_by_key_id(recipient_public_key_id)
        encrypted_session_key = AsymmetricEncryption.encrypt_with_public_key(public_key, session_key)
        return encrypted_session_key

    def decrypt_encrypted_session_key(self, encrypted_session_key, my_public_key_id, passphrase):
        private_key = privateKeyRing.get_key_by_key_id(my_public_key_id)
        session_key = AsymmetricEncryption.decrypt_with_private_key(private_key, encrypted_session_key, passphrase)
        return session_key

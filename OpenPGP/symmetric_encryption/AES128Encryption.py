import secrets
from cryptography.hazmat.primitives.ciphers import algorithms

from GlobalVariables import globalVariables
from symmetric_encryption.EncryptionAlgorithm import EncryptionAlgorithm

class AES128Encryption(EncryptionAlgorithm):

    def algorithm_code(self):
        return globalVariables.AES128

    def generate_session_key(self):
        session_key = secrets.token_bytes(16)
        return session_key

    def generate_initial_value(self):
        return b'0123456776543210'

    def get_algorithm(self, session_key):
        return algorithms.AES(session_key)

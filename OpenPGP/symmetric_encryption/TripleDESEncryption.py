import secrets
from cryptography.hazmat.primitives.ciphers import algorithms

from GlobalVariables import globalVariables
from symmetric_encryption.EncryptionAlgorithm import EncryptionAlgorithm

class TripleDESEncryption(EncryptionAlgorithm):

    def algorithm_code(self):
        return globalVariables.TripleDES

    def generate_session_key(self):
        session_key = secrets.token_bytes(24)
        return session_key

    def generate_initial_value(self):
        return b'01234567'

    def get_algorithm(self, session_key):
        return algorithms.TripleDES(session_key)

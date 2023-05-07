from PrivateKeyRing import privateKeyRing
from PublicKeyRing import publicKeyRing
from AsymmetricAlgo import AsymmetricAlgorithms

class EncryptionAlgorithm:

    def generate_session_key(self):
        pass

    def encrypt(self, message, recipient_public_key_id):
        pass

    def decrypt(self, message, my_public_key_id, passphrase):
        pass

    def encrypt_session_key(self, session_key, recipient_public_key_id):
        public_key = publicKeyRing.get_key_by_key_id(recipient_public_key_id)
        encrypted_session_key = AsymmetricAlgorithms.encrypt_with_public_key(public_key, session_key)
        return encrypted_session_key

    def decrypt_encrypted_session_key(self, encrypted_session_key, my_public_key_id, passphrase):
        private_key = privateKeyRing.get_key_by_key_id(my_public_key_id)
        session_key = AsymmetricAlgorithms.decrypt_with_private_key(private_key, encrypted_session_key, passphrase)
        return session_key

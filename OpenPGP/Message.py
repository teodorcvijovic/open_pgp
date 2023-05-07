import datetime

from EncryptionAlgorithm import EncryptionAlgorithm
class Message:

    def __init__(self, filename, data):
        self.filename = filename
        self.data = data
        self.timestamp = datetime.datetime.now()

        self.digest = None
        self.leading_octets = None
        self.sender_public_key_id = None
        self.signature_timestamp = None

        self.encrypted_session_key = None
        self.recipient_public_key_id = None

        # flags
        self.is_encrypted = False
        self.is_compressed = False
        self.is_signed = False
        self.is_radix64_converted = False

        self.compressed_data = None
        self.encrypted_data = None

    def content_to_string(self):
        return self.filename + '\n' + str(self.timestamp) + '\n' + self.data

    def signature_to_string(self):
        if not self.is_signed:
            return ''

        return str(self.signature_timestamp) + '\n' + str(self.sender_public_key_id) + '\n' + \
               self.leading_octets + '\n' + self.digest

    def get_data_for_encryption(self):
        if not self.is_compressed:
            return self.signature_to_string() + '\n'+ self.content_to_string()

        return self.compressed_data


    def encrypt(self, encryptionAlgorithm: EncryptionAlgorithm, recipient_public_key_id):
        if self.is_radix64_converted:
            return

        self.encrypted_data, self.encrypted_session_key = encryptionAlgorithm.encrypt(self, recipient_public_key_id)
        self.is_encrypted = True

    def decrypt(self, encryptionAlgorithm: EncryptionAlgorithm, my_public_key_id, passphrase):
        if not self.is_encrypted:
            return

        print(encryptionAlgorithm.decrypt(self, my_public_key_id, passphrase))

        self.is_encrypted = False



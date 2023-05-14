import ast
import base64
import datetime
import gzip
import io
import zipfile
import zlib

from asymmetric_encryption.AsymmetricEncryption import AsymmetricEncryption
from asymmetric_encryption.PrivateKeyRing import privateKeyRing
from asymmetric_encryption.PublicKeyRing import publicKeyRing
from exceptions.InvalidSignature import InvalidSignature
from symmetric_encryption.EncryptionAlgorithm import EncryptionAlgorithm
from cryptography.hazmat.primitives import hashes

class Message:

    def __init__(self, filename, data):
        # file
        self.filename = filename
        self.data = data
        self.timestamp = datetime.datetime.now()

        # # signature
        # self.digest = None
        # self.leading_octets = None
        # self.sender_public_key_id = None
        # self.signature_timestamp = None
        #
        # # session key
        # self.encrypted_session_key = None
        # self.recipient_public_key_id = None

        # # flags
        # self.is_encrypted = False           # 0b1000
        # self.is_compressed = False          # 0b0100
        # self.is_signed = False              # 0b0010
        # self.is_radix64_converted = False   # 0b0001

    def send(
        self,
        path,  # in this location a file named FILENAME.TXT will be created
        my_private_key_id,  # for signature
        passphrase,  # for signature
        encryptionAlgorithm: EncryptionAlgorithm,  # encryption
        recipient_public_key_id,  # encryption
        zip_message: bool,
        convert_to_radix64: bool
    ):
        message_for_sending = self.data

        # generate signature
        if my_private_key_id and passphrase:

            signature_timestamp = datetime.datetime.now()

            hasher = hashes.Hash(hashes.SHA1())
            hasher.update((message_for_sending + str(signature_timestamp)).encode('utf-8'))
            hashed_message = hasher.finalize()

            leading_two_bytes = hashed_message[:2]

            signature = AsymmetricEncryption.sign_with_private_key(
                private_key=privateKeyRing.get_key_by_key_id(my_private_key_id),
                data=hashed_message,
                passphrase=passphrase
            )

            my_key_id_to_send = my_private_key_id

            digest = str(signature_timestamp) + '\n' + str(my_key_id_to_send) + \
                     '\n' + str(leading_two_bytes) + '\n' + str(signature)
            message_for_sending = digest + '\n' + message_for_sending

        # compress message
        if zip_message:
            message_for_sending = gzip.compress(message_for_sending.encode('utf-8'))
        else:
            message_for_sending = message_for_sending.encode('utf-8')

        # encrypt message with session key, and encrypt session key
        encrypt = encryptionAlgorithm and recipient_public_key_id
        if encrypt:
            encrypted_data, encrypted_session_key = encryptionAlgorithm.encrypt(
                message_bytes=message_for_sending,
                recipient_public_key_id=recipient_public_key_id
            )
            message_for_sending = str(recipient_public_key_id) + '\n' + str(encrypted_session_key) + '\n' + str(encrypted_data)
        else:
            message_for_sending = str(message_for_sending)

        # radix64 conversion
        if convert_to_radix64:
            message_for_sending = base64.b64encode(message_for_sending.encode('utf-8')).decode('utf-8')

        # message header
        code_string: str = self.encode_operations(
            sign=my_private_key_id is not None and passphrase is not None,
            compress=zip_message,
            encrypt=encrypt,
            convert=convert_to_radix64
        )

        message_for_sending = code_string + '\n' + message_for_sending

        # create a file on given path
        with open(path + self.filename, "w") as file:
            file.write(message_for_sending)

        return message_for_sending

    # receives the message and return a Message object
    @classmethod
    def receive(
            cls,
            path,
            filename,
            encryptionAlgorithm: EncryptionAlgorithm,
            passphrase  # needed to access private key required for session key decryption
    ):
        with open(path + filename, "r") as file:
            received_message = file.read()

        code_string, data = received_message.split('\n', maxsplit=1)
        is_signed, is_compressed, is_encrypted, is_converted_to_radix64 = cls.decode_operations(code_string)

        if is_converted_to_radix64:
            # inverse conversion
            data = base64.b64decode(data).decode('utf-8')

        if is_encrypted:
            # decrypt
            my_public_key_id, encrypted_session_key, data = data.split('\n', maxsplit=2)
            my_public_key_id = int(my_public_key_id)
            # zato sto smo u fajl upisivali "b'NIZ_BAJTOVA'" moramo da kovertujemo ovaj string u pravi NIZ_BAJTOVA
            encrypted_session_key = bytes(ast.literal_eval(encrypted_session_key))
            data = bytes(ast.literal_eval(data))
            session_key = encryptionAlgorithm.decrypt_encrypted_session_key(
                encrypted_session_key,
                my_public_key_id,
                passphrase
            )
            data = encryptionAlgorithm.decrypt(session_key, data)
        else:
            data = bytes(ast.literal_eval(data))

        if is_compressed:
            data = gzip.decompress(data).decode('utf-8')
        else:
            data = data.decode('utf-8')

        if is_signed:
            # verify signature
            signature_timestamp, senders_key_id, leading_two_octets_from_message, signature, data = data.split('\n', 4)
            senders_key_id = int(senders_key_id)

            hasher = hashes.Hash(hashes.SHA1())
            hasher.update((data + str(signature_timestamp)).encode('utf-8'))
            hashed_message = hasher.finalize()

            leading_two_octets = hashed_message[:2]
            # convert leading two octets from message to string
            leading_two_octets_from_message = bytes(ast.literal_eval(leading_two_octets_from_message))
            signature = bytes(ast.literal_eval(signature))

            if leading_two_octets != leading_two_octets_from_message:
                raise InvalidSignature()

            senders_key = publicKeyRing.get_key_by_key_id(senders_key_id)
            signature_is_valid = AsymmetricEncryption.verify_signature(
                public_key=senders_key,
                signature=signature,
                hash=hashed_message,
            )
            if not signature_is_valid:
                raise InvalidSignature()

        return Message(filename=filename, data=data)

    # helper functions

    def encode_operations(self, sign: bool, compress: bool, encrypt: bool, convert: bool) -> str:
        num = 0
        if sign:
            num += 8
        if compress:
            num += 4
        if encrypt:
            num += 2
        if convert:
            num += 1
        return f"0b{num:04b}"

    @classmethod
    def decode_operations(self, code_string: str) -> tuple[bool, bool, bool, bool]:
        num = int(code_string, 2)
        f1 = (num & 0b1000) == 0b1000
        f2 = (num & 0b0100) == 0b0100
        f3 = (num & 0b0010) == 0b0010
        f4 = (num & 0b0001) == 0b0001
        return f1, f2, f3, f4



import ast
import base64
import datetime
import io
import zipfile

from symmetric_encryption.EncryptionAlgorithm import EncryptionAlgorithm

# TO DO
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
        encryptionAlgorithm: EncryptionAlgorithm, # encryption
        recipient_public_key_id,  # encryption
        zip_message: bool,
        convert_to_radix64: bool
    ):
        message_for_sending = self.data

        # generate signature
        if my_private_key_id:
            # TO DO
            pass

        # compress message
        if zip_message:
            compressed_buffer = io.BytesIO()
            with zipfile.ZipFile(compressed_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as my_zip:
                my_zip.writestr('my_compressed_string.txt', message_for_sending.encode('utf-8'))
            # compressed bytes
            message_for_sending = compressed_buffer.getvalue()
        else:
            message_for_sending = message_for_sending.encode('utf-8')

        # encrypt message with session key, and encrypt session key
        encrypt = encryptionAlgorithm and recipient_public_key_id
        if encrypt:
            encrypted_data, encrypted_session_key = encryptionAlgorithm.encrypt(
                message_string=message_for_sending,
                recipient_public_key_id=recipient_public_key_id
            )
            message_for_sending = str(encrypted_session_key) + '\n' + str(encrypted_data)

        # radix64 conversion
        if convert_to_radix64:
            message_for_sending = base64.b64encode(message_for_sending.encode('utf-8')).decode('utf-8')

        # message header
        code_string: str = self.encode_operations(
            sign=my_private_key_id is not None,
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
            my_public_key_id,  # needed to decrypt session key
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
            encrypted_session_key, data = data.split('\n', maxsplit=1)
            # zato sto smo u fajl upisivali "b'NIZ_BAJTOVA'" moramo da kovertujemo ovaj string u pravi NIZ_BAJTOVA
            encrypted_session_key = bytes(ast.literal_eval(encrypted_session_key))
            data = bytes(ast.literal_eval(data))
            session_key = encryptionAlgorithm.decrypt_encrypted_session_key(
                encrypted_session_key,
                my_public_key_id,
                passphrase
            )
            data = encryptionAlgorithm.decrypt(session_key, data)

        if is_compressed:
            # decompress
            data = bytes(ast.literal_eval(data))
            compressed_buffer = io.BytesIO(data)
            with zipfile.ZipFile(compressed_buffer, mode='r') as my_zip:
                # read the compressed file data as bytes
                decompressed_data = my_zip.read('my_compressed_string.txt')
            data = decompressed_data.decode('utf-8')

        if is_signed:
            # verify signature
            # TO DO
            pass

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



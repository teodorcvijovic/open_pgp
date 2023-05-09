from symmetric_encryption.AES128Encryption import AES128Encryption
from GlobalVariables import globalVariables
from Message import Message
from asymmetric_encryption.PrivateKey import PrivateKey
from asymmetric_encryption.AsymmetricEncryption import AsymmetricEncryption
from asymmetric_encryption.PrivateKeyRing import privateKeyRing
from asymmetric_encryption.PublicKeyRing import publicKeyRing

if __name__ == "__main__":

    # globalVariables.symmetric_algorithm = globalVariables.TripleDES
    # globalVariables.asymmetric_algorithm = globalVariables.RSA

    # public_key, private_key = AsymmetricEncryption.asymmetric_key_generate(globalVariables.DSA, 1024)
    # pk = PrivateKey(public_key, private_key, "ivan", "ivan@cv.com", "abcd", globalVariables.DSA)
    # print(pk.get_private_key("abcd"))
    # pk.save_public_key_to_pem()
    # pk.save_private_key_to_pem("abcd")

    pk = PrivateKey.load_from_file('key_pairs/private_keyring/13708595535030583297_private.pem',
                                   'key_pairs/private_keyring/13708595535030583297_public.pem', "abcd")
    privateKeyRing.save_key_existing(pk)

    public_key, private_key = AsymmetricEncryption.asymmetric_key_generate(globalVariables.RSA, 1024)
    publicKeyRing.save_key(public_key, 'teo', "teo@cv.com", globalVariables.RSA)
    publicKeyRing.save_key(pk.public_key, 'teo', "teo@cv.com", globalVariables.RSA)

    msg = Message("abc.txt", "Dobar dan")
    algo = AES128Encryption()

    #msg.encrypt(algo, 13708595535030583297)

    # msg.send(
    #     path='',
    #     my_private_key_id=None,
    #     encryptionAlgorithm=algo, recipient_public_key_id=13708595535030583297,
    #     zip_message=True,
    #     convert_to_radix64=False
    # )

    msg.send(
        path='',
        my_private_key_id=None,
        encryptionAlgorithm=algo, recipient_public_key_id=13708595535030583297,
        zip_message=True,
        convert_to_radix64=True
    )

    print(Message.receive(
        path='',
        filename='abc.txt',
        encryptionAlgorithm=algo,
        passphrase='abcd'
    ).data)


    # priv_key = privateKeyRing.get_key_by_key_id(13708595535030583297)
    # msg.decrypt(algo, 13708595535030583297, "abcd")

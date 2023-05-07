from AES128Encryption import AES128Encryption
from GlobalVariables import globalVariables
from Message import Message
from PrivateKey import PrivateKey
from AsymmetricAlgo import AsymmetricAlgorithms
from PrivateKeyRing import privateKeyRing
from PublicKeyRing import publicKeyRing
from TripleDESEncryption import TripleDESEncryption

if __name__ == "__main__":

    globalVariables.symmetric_algorithm = globalVariables.TripleDES
    globalVariables.asymmetric_algorithm = globalVariables.RSA

    #public_key, private_key = AsymmetricAlgorithms.asymmetric_key_generate("Teodor", "teo@cv.com", globalVariables.RSA, 1024)
    #pk = PrivateKey(public_key, private_key, "teo@cv.com", "abcd", globalVariables.RSA)
    #print(pk.get_private_key("abcd"))
    #pk.save_public_key_to_pem()
    #pk.save_private_key_to_pem("abcd")

    pk = PrivateKey.load_from_file('13708595535030583297_private.pem', '13708595535030583297_public.pem', "abcd")
    privateKeyRing.save_key_exisiting(pk)

    public_key, private_key = AsymmetricAlgorithms.asymmetric_key_generate("Teodor", "teo@cv.com", globalVariables.RSA, 1024)
    publicKeyRing.save_key(public_key, "teo@cv.com", globalVariables.RSA)
    publicKeyRing.save_key(pk.public_key, "teo@cv.com", globalVariables.RSA)

    msg = Message("abc", "Dobar dan")
    algo = AES128Encryption()

    msg.encrypt(algo, 13708595535030583297)

    print(msg.encrypted_data)

    priv_key = privateKeyRing.get_key_by_key_id(13708595535030583297)
    msg.decrypt(algo, 13708595535030583297, "abcd")

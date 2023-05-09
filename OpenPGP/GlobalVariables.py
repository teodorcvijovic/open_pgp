class GlobalVariables:
    AES128 = 0
    TripleDES = 1
    RSA = 2
    ElGamal = 3
    DSA = 4

    PRIVATE_KEYRING_PAIRS = './key_pairs/private_keyring'
    PUBLIC_KEYRING_PAIRS = './key_pairs/public_keyring'

    def __init__(self):
        self.asymmetric_algorithm = -1
        self.symmetric_algorithm = -1

    def set_asymmetric_algorithm(self, asymmetric):
        self.asymmetric_algorithm = asymmetric

    def set_symmetric_algorithm(self, symmetric):
        self.symmetric_algorithm = symmetric


globalVariables = GlobalVariables()

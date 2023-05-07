class GlobalVariables:

    AES128 = 0
    TripleDES = 1
    RSA = 2
    ElGamal = 3
    DSA = 4

    def __init__(self):
        self.asymmetric_algorithm = ""
        self.symmetric_algorithm = ""

    def set_asymmetric_algorithm(self, asymmetric):
        self.asymmetric_algorithm = asymmetric

    def set_symmetric_algorithm(self, symmetric):
        self.symmetric_algorithm = symmetric

globalVariables = GlobalVariables()
class PassphraseNotValid(Exception):

    def __init__(self):
        super(PassphraseNotValid, self).__init__('Passphrase is not valid!')
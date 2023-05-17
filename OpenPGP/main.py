import binascii
import sys

from cryptography.hazmat.primitives import serialization

from PyQt5.QtWidgets import (
    QApplication, QDialog, QMainWindow, QTableWidgetItem
)
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui

from GlobalVariables import globalVariables
from Message import Message
from asymmetric_encryption.AsymmetricEncryption import AsymmetricEncryption
from asymmetric_encryption.PrivateKey import PrivateKey
from asymmetric_encryption.PrivateKeyRing import privateKeyRing
from asymmetric_encryption.PublicKey import PublicKey
from asymmetric_encryption.PublicKeyRing import publicKeyRing
from exceptions.InvalidSignature import InvalidSignature

from exceptions.PassphraseNotValid import PassphraseNotValid
from exceptions.UnsupportedSymmetricAlgorithm import UnsupportedSymmetricAlgorithm

from gui.main_window_ui import Ui_MainWindow
from symmetric_encryption.AES128Encryption import AES128Encryption
from symmetric_encryption.TripleDESEncryption import TripleDESEncryption


class Window(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.GenerateButton.clicked.connect(self.generate_keys)
        self.importPrivateKeyButton.clicked.connect(self.import_private_key)
        self.importPublicKeyButton.clicked.connect(self.import_public_key)
        self.sendMessageButton.clicked.connect(self.send_message_button_clicked)
        self.loadMessageButton.clicked.connect(self.receive_message_button_clicked)

        self.privateKeyRingTable.setColumnCount(10)
        self.privateKeyRingTable.setHorizontalHeaderLabels(
            ['Timestamp', 'Key ID', 'Username', 'Email', 'Public Key', 'E(H(p), Private Key)', 'Algorithm', '', '', ''])

        self.publicKeyRingTable.setColumnCount(8)
        self.publicKeyRingTable.setHorizontalHeaderLabels(
            ['Timestamp', 'Key ID', 'Username', 'Email', 'Public Key', 'Algorithm', '', ''])

        self.privateKeyToShow = None
        self.passphrase = ''
        self.message = None


    def generate_keys(self):
        globalVariables.name = self.Name.toPlainText()
        globalVariables.email = self.Email.toPlainText()
        if not self.AsymmetricAlgoGroup.checkedButton() or not self.KeySizeGroup.checkedButton():
            self.ErrorMsg.setText('Invalid input!')
            return

        globalVariables.set_algoChecked(self.AsymmetricAlgoGroup.checkedButton().text())
        globalVariables.set_keySizeChecked(self.KeySizeGroup.checkedButton().text())

        # check if the text is not empty and a radio button is selected
        if globalVariables.email and globalVariables.name and globalVariables.algoChecked and globalVariables.keySizeChecked:
            self.passphraseDialogOpen()
        else:
            self.ErrorMsg.setText('Fill out all fields!')

    def import_private_key(self):
        private_key_path = self.privateKeyImportPath.toPlainText()
        public_key_path = self.publicKeyImportPath.toPlainText()
        passphrase = self.passphraseImportField.toPlainText()

        if not private_key_path or not public_key_path or not passphrase or len(private_key_path) == 0 or len(
                public_key_path) == 0 or len(passphrase) == 0:
            self.privateKeyRingError.setText('Fill out all fields required for key import!')
            return

        private_key = PrivateKey.load_from_file(private_key_filename=private_key_path,
                                                public_key_filename=public_key_path, passphrase=passphrase)
        privateKeyRing.save_key_existing(private_key)

        self.populate_private_key_table()
        self.privateKeyRingError.setText('')

    def import_public_key(self):
        public_key_path = self.importPathForPublicKey.toPlainText()

        if not public_key_path or len(public_key_path) == 0:
            self.publicKeyRingError.setText('Path is required!')
            return

        public_key = PublicKey.load_from_file(public_key_filename=public_key_path)
        publicKeyRing.add_key(public_key)

        self.populate_public_key_table()
        self.publicKeyRingError.setText('')

    def enterPassphraseSendMessageDialogOpen(self):
        dialog = EnterPassphraseSendMessage(self)
        dialog.exec()

    def passphraseDialogOpen(self):
        dialog = PassphraseDialog(self)
        dialog.exec()

    def showPrivateKeyDialogOpen(self):
        button = self.sender()
        row = self.privateKeyRingTable.indexAt(button.pos()).row()
        key_id_item = self.privateKeyRingTable.item(row, 1)
        key_id = int(key_id_item.text())
        self.privateKeyToShow = privateKeyRing.get_key_by_key_id(key_id)

        dialog = ShowPrivateKeyDialog(self)
        dialog.exec()
        self.privateKeyToShow = None

    def deletePrivateKeyButtonClicked(self):
        button = self.sender()
        row = self.privateKeyRingTable.indexAt(button.pos()).row()
        key_id_item = self.privateKeyRingTable.item(row, 1)
        key_id = int(key_id_item.text())
        privateKeyRing.delete_key_pair(key_id)
        self.populate_private_key_table()

    def deletePublicKeyButtonClicked(self):
        button = self.sender()
        row = self.publicKeyRingTable.indexAt(button.pos()).row()
        key_id_item = self.publicKeyRingTable.item(row, 1)
        key_id = int(key_id_item.text())
        publicKeyRing.delete_key(key_id)
        self.populate_public_key_table()

    def exportPrivateKeyButtonClicked(self):
        passphrase = self.passphraseImportField.toPlainText()
        if not passphrase:
            self.privateKeyRingError.setText('Passphrase is required for export!')

        button = self.sender()
        row = self.privateKeyRingTable.indexAt(button.pos()).row()
        key_id_item = self.privateKeyRingTable.item(row, 1)
        key_id = int(key_id_item.text())

        private_key = privateKeyRing.get_key_by_key_id(key_id)
        private_key.save_public_key_to_pem()
        try:
            private_key.save_private_key_to_pem(passphrase)
            self.privateKeyRingError.setText('Key exported!')
        except PassphraseNotValid:
            self.privateKeyRingError.setText('Passphrase is not valid!')

    def exportPublicKeyButtonClicked(self):
        button = self.sender()
        row = self.publicKeyRingTable.indexAt(button.pos()).row()
        key_id_item = self.publicKeyRingTable.item(row, 1)
        key_id = int(key_id_item.text())

        public_key = publicKeyRing.get_key_by_key_id(key_id)
        public_key.save_public_key_to_pem()
        self.publicKeyRingError.setText('Key exported!')

    def populate_private_key_table(self):
        self.privateKeyRingTable.setRowCount(len(privateKeyRing.keys))
        for row, private_key in enumerate(privateKeyRing.keys):
            public_key_hex = binascii.hexlify(private_key.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8')

            encrypted_private_key_hex = binascii.hexlify(private_key.encrypted_private_key).decode('utf-8')

            row_data = [
                str(private_key.timestamp),
                str(private_key.key_id),
                private_key.username,
                private_key.email,
                str(public_key_hex),
                encrypted_private_key_hex,
                globalVariables.decode_algorithm_code(private_key.derived_from_algorithm)
            ]
            for col, data in enumerate(row_data):
                if col == 7:
                    break
                item = QTableWidgetItem(data)
                self.privateKeyRingTable.setItem(row, col, item)

            # add delete button
            button = QtWidgets.QPushButton(self.privateKeyRingTable)
            button.setText('Delete')
            self.privateKeyRingTable.setCellWidget(row, 7, button)
            button.clicked.connect(self.deletePrivateKeyButtonClicked)

            # export button
            button = QtWidgets.QPushButton(self.privateKeyRingTable)
            button.setText('Export')
            self.privateKeyRingTable.setCellWidget(row, 8, button)
            button.clicked.connect(self.exportPrivateKeyButtonClicked)

            # show private key button
            button = QtWidgets.QPushButton(self.privateKeyRingTable)
            button.setText('Show private key')
            self.privateKeyRingTable.setCellWidget(row, 9, button)
            button.clicked.connect(self.showPrivateKeyDialogOpen)

    def populate_public_key_table(self):
        self.publicKeyRingTable.setRowCount(len(publicKeyRing.keys))
        for row, public_key in enumerate(publicKeyRing.keys):
            public_key_hex = binascii.hexlify(public_key.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8')

            row_data = [
                str(public_key.timestamp),
                str(public_key.key_id),
                public_key.username,
                public_key.email,
                str(public_key_hex),
                globalVariables.decode_algorithm_code(public_key.derived_from_algorithm)
            ]
            for col, data in enumerate(row_data):
                if col == 6:
                    break
                item = QTableWidgetItem(data)
                self.publicKeyRingTable.setItem(row, col, item)

            # add delete button
            button = QtWidgets.QPushButton(self.publicKeyRingTable)
            button.setText('Delete')
            self.publicKeyRingTable.setCellWidget(row, 6, button)
            button.clicked.connect(self.deletePublicKeyButtonClicked)

            # export button
            button = QtWidgets.QPushButton(self.publicKeyRingTable)
            button.setText('Export')
            self.publicKeyRingTable.setCellWidget(row, 7, button)
            button.clicked.connect(self.exportPublicKeyButtonClicked)

    def send_message_button_clicked(self):
        filename = self.messageTitle.toPlainText()
        data = self.messageContentTextBox.toPlainText()

        message = Message(filename=filename, data=data)

        path = self.pathTextBox.toPlainText()
        my_private_key_id = self.privateKeyTextBox.toPlainText()
        if my_private_key_id:
            my_private_key_id = int(my_private_key_id)
        zip_message = self.zipCheckbox.isChecked()
        symmetric_algo = self.SymmetricAlgoGroup.checkedButton().text()

        encryptionAlgorithm = None
        if symmetric_algo == '3DES':
            encryptionAlgorithm = TripleDESEncryption()
        elif symmetric_algo == 'AES128':
            encryptionAlgorithm = AES128Encryption()

        recipient_public_key_id = self.publicKeyTextbox.toPlainText()
        if recipient_public_key_id:
            recipient_public_key_id = int(recipient_public_key_id)
        convert_to_radix64 = self.radix64Checkbox.isChecked()

        if my_private_key_id:
            # enter passphrase to sign the message with private key
            self.enterPassphraseSendMessageDialogOpen()

        try:
            message.send(
                path=path,
                my_private_key_id=my_private_key_id,
                passphrase=self.passphrase,
                encryptionAlgorithm=encryptionAlgorithm,
                recipient_public_key_id=recipient_public_key_id,
                zip_message=zip_message,
                convert_to_radix64=convert_to_radix64,
            )
            self.errorLabel.setText('Message is sent!')
        except PassphraseNotValid:
            self.errorLabel.setText('Invalid passphrase!\nMessage cannot be sent!')

        self.passphrase = ''

    def receive_message_button_clicked(self):
        try:
            path = self.receiveMessagePath.toPlainText()
            if Message.passphrase_is_required_for_session_key_decryption(path):
                dialog = EnterPassphraseReceiveMessage(self)
                dialog.exec()

            self.message = Message.receive(
                path=path,
                passphrase=self.passphrase
            )

            dialog = MessageDialog(self)
            dialog.exec()

            self.message = None

        except FileNotFoundError:
            self.errorMsgReceive.setText('File is not found!')
        except InvalidSignature:
            self.errorMsgReceive.setText('Invalid signature!')
        except UnsupportedSymmetricAlgorithm:
            self. self.errorMsgReceive.setText('Unsupported symmetric algorithm!')
        except PassphraseNotValid:
            self. self.errorMsgReceive.setText('Passphrase is not valid!')
        # TO DO: add case for invalid decryption

        self.passphrase = ''

class MessageDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi("ui/MessageDialog.ui", self)
        self.saveMessageButton.clicked.connect(self.on_OK)
        self.cancelButton.clicked.connect(self.on_Cancel)

        self.filenameTextBox.setPlainText(self.parent().message.filename)
        self.messageContentTextBox.setPlainText(self.parent().message.data)

    def on_OK(self):
        filename = self.filenameTextBox.toPlainText()
        data = self.messageContentTextBox.toPlainText()
        path = self.pathTextBox.toPlainText()

        with open(path + filename, "w") as file:
            file.write(data)

        self.msg.setText('Message is saved!')

    def on_Cancel(self):
        self.close()

class EnterPassphraseReceiveMessage(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi("ui/PassphraseDialog.ui", self)
        self.OKBox.accepted.connect(self.on_accepted)

    def on_accepted(self):
        self.parent().passphrase = self.PassphraseText.toPlainText()

    def on_canceled(self):
        self.close()

class EnterPassphraseSendMessage(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi("ui/EnterPassphraseSendMessage.ui", self)
        self.okButton.clicked.connect(self.on_OK)
        self.cancelButton.clicked.connect(self.on_Cancel)

    def on_OK(self):
        passphrase = self.passphraseTextBox.toPlainText()
        self.parent().passphrase = passphrase
        self.close()

    def on_Cancel(self):
        self.close()

class ShowPrivateKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi("ui/ShowPrivateKeyDialog.ui", self)
        self.showPrivateKeyDialogOK.clicked.connect(self.on_OK)
        self.showPrivateKeyDialogCancel.clicked.connect(self.on_Cancel)

    def on_OK(self):
        passphrase = self.showPrivateKeyDialogPassphrase.toPlainText()
        try:
            decrypted_private_key = self.parent().privateKeyToShow.get_private_key(passphrase)

            private_key_bytes = decrypted_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
            )

            private_key_hex = binascii.hexlify(private_key_bytes).decode('utf-8')

            self.showPrivateKeyDialogPrivateKey.setPlainText(private_key_hex)
        except PassphraseNotValid:
            self.showPrivateKeyDialogPrivateKey.setPlainText('Access denied: Invalid passphrase')

    def on_Cancel(self):
        self.parent().privateKeyToShow = None
        self.close()

class PassphraseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi("ui/PassphraseDialog.ui", self)
        globalVariables.passphrase = self.PassphraseText.toPlainText()
        self.OKBox.accepted.connect(self.on_accepted)

    def on_accepted(self):
        public_key, private_key = AsymmetricEncryption.asymmetric_key_generate(
            algorithm=globalVariables.algoChecked,
            key_length=globalVariables.keySizeChecked
        )
        privateKeyRing.save_key(
            public_key=public_key,
            private_key=private_key,
            username=globalVariables.name,
            email=globalVariables.email,
            passphrase=self.PassphraseText.toPlainText(),
            algo=globalVariables.algoChecked
        )

        self.parent().populate_private_key_table()

        self.parent().ErrorMsg.setText('Keypair is successfully generated!')

    def on_canceled(self):
        self.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())

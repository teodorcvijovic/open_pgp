# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui/EnterPassphraseSendMessage.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_enterPassphraseSendMessage(object):
    def setupUi(self, enterPassphraseSendMessage):
        enterPassphraseSendMessage.setObjectName("enterPassphraseSendMessage")
        enterPassphraseSendMessage.resize(618, 224)
        self.cancelButton = QtWidgets.QPushButton(enterPassphraseSendMessage)
        self.cancelButton.setGeometry(QtCore.QRect(290, 130, 111, 41))
        self.cancelButton.setObjectName("cancelButton")
        self.okButton = QtWidgets.QPushButton(enterPassphraseSendMessage)
        self.okButton.setGeometry(QtCore.QRect(180, 130, 101, 41))
        self.okButton.setObjectName("okButton")
        self.passphraseTextBox = QtWidgets.QPlainTextEdit(enterPassphraseSendMessage)
        self.passphraseTextBox.setGeometry(QtCore.QRect(130, 80, 321, 31))
        self.passphraseTextBox.setObjectName("passphraseTextBox")
        self.label = QtWidgets.QLabel(enterPassphraseSendMessage)
        self.label.setGeometry(QtCore.QRect(180, 50, 331, 20))
        self.label.setObjectName("label")

        self.retranslateUi(enterPassphraseSendMessage)
        QtCore.QMetaObject.connectSlotsByName(enterPassphraseSendMessage)

    def retranslateUi(self, enterPassphraseSendMessage):
        _translate = QtCore.QCoreApplication.translate
        enterPassphraseSendMessage.setWindowTitle(_translate("enterPassphraseSendMessage", "Dialog"))
        self.cancelButton.setText(_translate("enterPassphraseSendMessage", "Cancel"))
        self.okButton.setText(_translate("enterPassphraseSendMessage", "OK"))
        self.label.setText(_translate("enterPassphraseSendMessage", "Enter passphrase to sign the message:"))
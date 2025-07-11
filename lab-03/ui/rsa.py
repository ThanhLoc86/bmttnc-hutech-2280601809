# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './ui/rsa.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import os
os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = "../platforms"

class Ui_RSA_Cipher(object):
    def setupUi(self, RSA_Cipher):
        RSA_Cipher.setObjectName("RSA_Cipher")
        RSA_Cipher.resize(800, 400)
        self.centralwidget = QtWidgets.QWidget(RSA_Cipher)
        self.centralwidget.setObjectName("centralwidget")
        self.label_title = QtWidgets.QLabel(self.centralwidget)
        self.label_title.setGeometry(QtCore.QRect(300, 20, 200, 30))
        self.label_title.setText("")
        self.label_title.setAlignment(QtCore.Qt.AlignCenter)
        self.label_title.setObjectName("label_title")
        self.btn_generate_keys = QtWidgets.QPushButton(self.centralwidget)
        self.btn_generate_keys.setGeometry(QtCore.QRect(550, 20, 100, 30))
        self.btn_generate_keys.setObjectName("btn_generate_keys")
        self.label_plain_text = QtWidgets.QLabel(self.centralwidget)
        self.label_plain_text.setGeometry(QtCore.QRect(50, 80, 100, 30))
        self.label_plain_text.setObjectName("label_plain_text")
        self.txt_plain_text = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.txt_plain_text.setGeometry(QtCore.QRect(150, 80, 250, 80))
        self.txt_plain_text.setObjectName("txt_plain_text")
        self.label_cipher_text = QtWidgets.QLabel(self.centralwidget)
        self.label_cipher_text.setGeometry(QtCore.QRect(50, 180, 100, 30))
        self.label_cipher_text.setObjectName("label_cipher_text")
        self.txt_cipher_text = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.txt_cipher_text.setGeometry(QtCore.QRect(150, 180, 250, 80))
        self.txt_cipher_text.setObjectName("txt_cipher_text")
        self.btn_encrypt = QtWidgets.QPushButton(self.centralwidget)
        self.btn_encrypt.setGeometry(QtCore.QRect(150, 280, 100, 30))
        self.btn_encrypt.setObjectName("btn_encrypt")
        self.btn_decrypt = QtWidgets.QPushButton(self.centralwidget)
        self.btn_decrypt.setGeometry(QtCore.QRect(300, 280, 100, 30))
        self.btn_decrypt.setObjectName("btn_decrypt")
        self.label_information = QtWidgets.QLabel(self.centralwidget)
        self.label_information.setGeometry(QtCore.QRect(450, 80, 100, 30))
        self.label_information.setObjectName("label_information")
        self.txt_information = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.txt_information.setGeometry(QtCore.QRect(550, 80, 200, 80))
        self.txt_information.setObjectName("txt_information")
        self.label_signature = QtWidgets.QLabel(self.centralwidget)
        self.label_signature.setGeometry(QtCore.QRect(450, 180, 100, 30))
        self.label_signature.setObjectName("label_signature")
        self.txt_signature = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.txt_signature.setGeometry(QtCore.QRect(550, 180, 200, 80))
        self.txt_signature.setObjectName("txt_signature")
        self.btn_sign = QtWidgets.QPushButton(self.centralwidget)
        self.btn_sign.setGeometry(QtCore.QRect(550, 280, 100, 30))
        self.btn_sign.setObjectName("btn_sign")
        self.btn_verify = QtWidgets.QPushButton(self.centralwidget)
        self.btn_verify.setGeometry(QtCore.QRect(650, 280, 100, 30))
        self.btn_verify.setObjectName("btn_verify")
        RSA_Cipher.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(RSA_Cipher)
        self.statusbar.setObjectName("statusbar")
        RSA_Cipher.setStatusBar(self.statusbar)

        self.retranslateUi(RSA_Cipher)
        QtCore.QMetaObject.connectSlotsByName(RSA_Cipher)

    def retranslateUi(self, RSA_Cipher):
        _translate = QtCore.QCoreApplication.translate
        RSA_Cipher.setWindowTitle(_translate("RSA_Cipher", "RSA Cipher"))
        self.btn_generate_keys.setText(_translate("RSA_Cipher", "Generate Keys"))
        self.label_plain_text.setText(_translate("RSA_Cipher", "Plain Text:"))
        self.label_cipher_text.setText(_translate("RSA_Cipher", "CipherText:"))
        self.btn_encrypt.setText(_translate("RSA_Cipher", "Encrypt"))
        self.btn_decrypt.setText(_translate("RSA_Cipher", "Decrypt"))
        self.label_information.setText(_translate("RSA_Cipher", "Information:"))
        self.label_signature.setText(_translate("RSA_Cipher", "Signature:"))
        self.btn_sign.setText(_translate("RSA_Cipher", "Sign"))
        self.btn_verify.setText(_translate("RSA_Cipher", "Verify"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    RSA_Cipher = QtWidgets.QMainWindow()
    ui = Ui_RSA_Cipher()
    ui.setupUi(RSA_Cipher)
    RSA_Cipher.show()
    sys.exit(app.exec_())

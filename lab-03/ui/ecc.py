# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './ui/ecc.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import os
os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = "../platforms"

class Ui_ECCCipher(object):
    def setupUi(self, ECCCipher):
        ECCCipher.setObjectName("ECCCipher")
        ECCCipher.resize(400, 300)
        self.centralwidget = QtWidgets.QWidget(ECCCipher)
        self.centralwidget.setObjectName("centralwidget")
        self.label_title = QtWidgets.QLabel(self.centralwidget)
        self.label_title.setGeometry(QtCore.QRect(120, 10, 160, 30))
        self.label_title.setAlignment(QtCore.Qt.AlignCenter)
        font = QtGui.QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label_title.setFont(font)
        self.label_title.setObjectName("label_title")
        self.btn_generate_keys = QtWidgets.QPushButton(self.centralwidget)
        self.btn_generate_keys.setGeometry(QtCore.QRect(280, 10, 100, 30))
        self.btn_generate_keys.setObjectName("btn_generate_keys")
        self.label_information = QtWidgets.QLabel(self.centralwidget)
        self.label_information.setGeometry(QtCore.QRect(20, 60, 80, 30))
        self.label_information.setObjectName("label_information")
        self.txt_information = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.txt_information.setGeometry(QtCore.QRect(120, 60, 260, 60))
        self.txt_information.setObjectName("txt_information")
        self.label_signature = QtWidgets.QLabel(self.centralwidget)
        self.label_signature.setGeometry(QtCore.QRect(20, 140, 80, 30))
        self.label_signature.setObjectName("label_signature")
        self.txt_signature = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.txt_signature.setGeometry(QtCore.QRect(120, 140, 260, 60))
        self.txt_signature.setObjectName("txt_signature")
        self.btn_sign = QtWidgets.QPushButton(self.centralwidget)
        self.btn_sign.setGeometry(QtCore.QRect(120, 220, 100, 30))
        self.btn_sign.setObjectName("btn_sign")
        self.btn_verify = QtWidgets.QPushButton(self.centralwidget)
        self.btn_verify.setGeometry(QtCore.QRect(240, 220, 100, 30))
        self.btn_verify.setObjectName("btn_verify")
        ECCCipher.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(ECCCipher)
        self.statusbar.setObjectName("statusbar")
        ECCCipher.setStatusBar(self.statusbar)

        self.retranslateUi(ECCCipher)
        QtCore.QMetaObject.connectSlotsByName(ECCCipher)

    def retranslateUi(self, ECCCipher):
        _translate = QtCore.QCoreApplication.translate
        ECCCipher.setWindowTitle(_translate("ECCCipher", "ECC Cipher"))
        self.label_title.setText(_translate("ECCCipher", "ECC CIPHER"))
        self.btn_generate_keys.setText(_translate("ECCCipher", "Generate Keys"))
        self.label_information.setText(_translate("ECCCipher", "Information:"))
        self.label_signature.setText(_translate("ECCCipher", "Signature:"))
        self.btn_sign.setText(_translate("ECCCipher", "Sign"))
        self.btn_verify.setText(_translate("ECCCipher", "Verify"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    ECCCipher = QtWidgets.QMainWindow()
    ui = Ui_ECCCipher()
    ui.setupUi(ECCCipher)
    ECCCipher.show()
    sys.exit(app.exec_())

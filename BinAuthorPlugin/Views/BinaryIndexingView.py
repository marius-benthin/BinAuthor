from subprocess import Popen
from os.path import dirname, realpath
from PyQt5 import QtCore, QtWidgets, uic

from pluginConfigurations import getPythonPath


class BinaryIndexing():
   
    def create(self):
        self.wid = QtWidgets.QWidget()
        binaryUIPath = os.path.dirname(os.path.realpath(__file__)) + "\\UI\\BinaryIndexing.ui"
        file = QtCore.QFile(binaryUIPath)
        file.open(QtCore.QFile.ReadOnly)
        myWidget = uic.loadUi(file, self.wid)
        self.wid.setWindowTitle('Binary Indexing')
        pushButtons = self.wid.findChildren(QtWidgets.QPushButton)
        
        for button in pushButtons:
            if "selectFolder" in button.objectName():
                button.clicked.connect(self.selectFolder)
            elif "closeForm" in button.objectName():
                button.clicked.connect(self.close)
            elif "indexAuthors" in button.objectName():
                button.clicked.connect(self.indexBinaries)
        file.close()
        
    def selectFolder(self):
        print("Selecting Folder!")
        folder = QtWidgets.QFileDialog.getExistingDirectory(options=0)
        self.lineEditors = self.wid.findChildren(QtWidgets.QLineEdit)
        
        for textbox in self.lineEditors:
            if "FolderInput" in textbox.objectName():
                textbox.setText(folder)
                self.folderInput = textbox
        
    def indexBinaries(self):
        print("Indexing Binaries!")
        indexFolder = self.folderInput.text()
        locationOfScript = os.path.dirname(os.path.realpath(__file__))[:-5] + "ExternalScripts\indexFiles.py" 
        DETACHED_PROCESS = 0x00000008
        self.radioButton = self.wid.findChildren(QtWidgets.QRadioButton)
        multiple = 0
        
        authorName = None
        for textbox in self.lineEditors:
            if "AuthorInput" in textbox.objectName():
                if textbox.isEnabled() == True:
                    authorName = textbox.text()
        
        
        for radio in self.radioButton:
            if "multiple" in radio.objectName():
                if radio.isChecked():
                    multiple = 1
        if authorName != None:
            Popen([pluginConfigurations.getPythonPath(),locationOfScript,indexFolder,str(multiple),authorName],close_fds=True, creationflags=DETACHED_PROCESS)
        else:
            Popen([pluginConfigurations.getPythonPath(),locationOfScript,indexFolder,str(multiple)],close_fds=True, creationflags=DETACHED_PROCESS)

    def close(self):
        self.wid.close()
        print("Closed")


    def show(self):
        """Creates the form is not created or focuses it if it was"""
        self.wid.show()

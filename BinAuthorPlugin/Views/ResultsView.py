import os
from PyQt5 import QtGui, QtWidgets, QtCore, uic

from idaapi import PluginForm


class Results(PluginForm):
    def returnColor(self,percentage):
        percentage = (1-percentage) * 100
        #R = (255 * percentage) / 100
        #G = (255 * (100 - percentage)) / 100
        #B = 0
        
        if percentage < 50:
            R = 255 * (percentage/50)
            G = 255
        else:
            R = 255
            G = 255 * ((50 - percentage % 50) / 50)
        B = 0
        return QtGui.QColor(R,G,B)
    def OnCreate(self,form):
        self.parent = self.FormToPySideWidget(form)
        self.wid = QtWidgets.QWidget()
        binaryUIPath = os.path.dirname(os.path.realpath(__file__)) + "\\UI\\ResultsView.ui"
        file = QtCore.QFile(binaryUIPath)
        file.open(QtCore.QFile.ReadOnly)
        myWidget = uic.loadUi(file, self.wid)
        # Grid
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(myWidget)

        
        comboBoxes = self.wid.findChildren(QtWidgets.QComboBox)
        tableView = self.wid.findChildren(QtWidgets.QTableWidget)
        for combo in comboBoxes:
            if "comboBox" in combo.objectName():
                combo.insertItems(0,["1","5","10","15","50","100"])
                
        for table in tableView:
            if "tableWidget" in table.objectName():
                rowCount = table.rowCount()
                for row in range(0,rowCount):
                    value = float(table.item(row,1).text())
                    table.item(row,1).setBackground(self.returnColor(value))
                    table.item(row,0).setBackground(self.returnColor(value))
                    
        
        file.close()
        self.parent.setLayout(layout)
    '''    
    def selectFolder(self):
        print("Selecting Folder!")
        folder = QtGui.QFileDialog.getExistingDirectory(options=0)
        self.lineEditors = self.wid.findChildren(QtGui.QLineEdit)
        
        for textbox in self.lineEditors:
            if "FolderInput" in textbox.objectName():
                textbox.setText(folder)
                self.folderInput = textbox
        
    def results(self):
        print("Indexing Binaries!")
        indexFolder = self.folderInput.text()
        locationOfScript = os.path.dirname(os.path.realpath(__file__))[:-5] + "ExternalScripts\indexFiles.py" 
        DETACHED_PROCESS = 0x00000008
        self.radioButton = self.wid.findChildren(QtGui.QRadioButton)
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
            Popen(["python",locationOfScript,indexFolder,str(multiple),authorName],close_fds=True, creationflags=DETACHED_PROCESS)
        else:
            Popen(["python",locationOfScript,indexFolder,str(multiple)],close_fds=True, creationflags=DETACHED_PROCESS)

    def close(self):
        self.wid.close()
        print("Closed")

'''
    def Show(self, caption="Results View", options=PluginForm.WOPN_PERSIST):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self, caption=caption, options=options)

from pathlib import Path
from subprocess import Popen
from PyQt5 import QtCore, QtWidgets, uic

from ida_kernwin import action_handler_t, AST_ENABLE_ALWAYS

from config import Config


class BinaryIndexingHandler(action_handler_t):

    """
    Action handler that initializes BinaryIndexing for IDA Pro GUI
    """

    def __init__(self):
        action_handler_t.__init__(self)
        self.binary_indexing = BinaryIndexing()

    def activate(self, ctx):
        self.binary_indexing.create()
        self.binary_indexing.show()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class BinaryIndexing:

    """
    Indexes all authors and their developed binaries
    """

    def __init__(self):
        _config: Config = Config()
        self.file_dir_path = Path(__file__).parent.absolute()
        self.radioButton = None
        self.folderInput = None
        self.lineEditors = None
        self.wid = None

    def create(self):
        """
        Create a view for binary indexing
        """
        # load UI file
        ui_path = self.file_dir_path / "UI" / "BinaryIndexing.ui"
        file = QtCore.QFile(str(ui_path))
        file.open(QtCore.QFile.ReadOnly)
        # create window widget
        self.wid = QtWidgets.QWidget()
        uic.loadUi(file, self.wid)
        self.wid.setWindowTitle("Binary Indexing")
        # connect buttons with actions
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
        """
        Select the folder that contains the binaries
        """
        folder = QtWidgets.QFileDialog.getExistingDirectory()
        self.lineEditors = self.wid.findChildren(QtWidgets.QLineEdit)
        for textbox in self.lineEditors:
            if "FolderInput" in textbox.objectName():
                textbox.setText(folder)
                self.folderInput = textbox

    def indexBinaries(self):
        """
        Index all binaries for each author
        """
        indexFolder = self.folderInput.text()
        locationOfScript = self.file_dir_path.parent / "ExternalScripts" / "indexFiles.py"
        DETACHED_PROCESS = 0x00000008
        self.radioButton = self.wid.findChildren(QtWidgets.QRadioButton)
        multiple = 0

        authorName = None
        for textbox in self.lineEditors:
            if "AuthorInput" in textbox.objectName():
                if textbox.isEnabled():
                    authorName = textbox.text()

        for radio in self.radioButton:
            if "multiple" in radio.objectName():
                if radio.isChecked():
                    multiple = 1
        if authorName is not None:
            Popen([getPythonPath(), locationOfScript, indexFolder, str(multiple), authorName], close_fds=True,
                  creationflags=DETACHED_PROCESS)
        else:
            Popen([getPythonPath(), locationOfScript, indexFolder, str(multiple)], close_fds=True,
                  creationflags=DETACHED_PROCESS)

    def close(self):
        """
        Close view for binary indexing
        """
        self.wid.close()

    def show(self):
        """
        Open or focus binary indexing view
        """
        self.wid.show()

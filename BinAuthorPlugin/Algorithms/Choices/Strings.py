from pymongo.collection import Collection

from ida_nalt import get_root_filename, STRTYPE_C, STRTYPE_C_16
from idautils import GetInputFileMD5, Strings
from ida_kernwin import action_handler_t, AST_ENABLE_ALWAYS

from Database.mongodb import MongoDB, Collections


class CustomStringsHandler(action_handler_t):

    def __init__(self):
        action_handler_t.__init__(self)
        self.custom_strings = CustomStrings()

    def activate(self, ctx):
        self.custom_strings.CustomStrings()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class CustomStrings:

    def __init__(self, authorName: str = None):
        self.fileName: str = get_root_filename()
        self.fileMD5: bytes = GetInputFileMD5()
        # use ARGV[1] if it was passed with authorName else fileName
        self.authorName: str = self.fileName if authorName is None else authorName
        self.collection: Collection = MongoDB(Collections.strings).collection

        self.allStrings = []

    def CustomStrings(self):
        output = self.getAllStrings()
        self.collection.insert_one(output)

    def getAllStrings(self):
        self.allStrings = self.getAllStringsA()
        output = {"Strings": self.allStrings, "FileName": self.fileName, "FileMD5": self.fileMD5,
                  "Author Name": self.authorName}

        return output

    @staticmethod
    def getAllStringsA():
        strings = Strings(default_setup=False)
        allStrings = []
        strings.setup(
            strtypes=[STRTYPE_C, STRTYPE_C_16], ignore_instructions=True, display_only_existing_strings=True, minlen=4
        )
        for string in strings:
            allStrings.append(str(string))
        return allStrings

from pymongo import MongoClient

from ida_nalt import get_root_filename
from idautils import GetInputFileMD5, Strings


class _Strings():
    def __init__(self):
        self.allStrings = []
        self.client = MongoClient('localhost', 27017)
        self.db = self.client.BinAuthor
        self.collection = self.db.Strings
        
        self.fileName = idaapi.get_root_filename()
        self.fileMD5 = idautils.GetInputFileMD5()
        self.authorName = self.fileName
        
    def _Strings(self):
        strings = idautils.Strings(default_setup = False)
        strings.setup(strtypes=Strings.STR_C | Strings.STR_UNICODE, ignore_instructions = True, display_only_existing_strings = True,minlen=4)
        for string in strings:
            self.allStrings.append(str(string))
        
        output = {"Strings": self.allStrings}      
        output["FileName"] = self.fileName
        output["FileMD5"] = self.fileMD5
        output["Author Name"] = self.authorName
        
        self.collection.insert(output)
        
    def getAllStrings(self):
        strings = idautils.Strings(default_setup = False)
        strings.setup(strtypes=Strings.STR_C | Strings.STR_UNICODE, ignore_instructions = True, display_only_existing_strings = True,minlen=4)
        for string in strings:
            self.allStrings.append(str(string))
        
        output = {"Strings": self.allStrings}      
        output["FileName"] = self.fileName
        output["FileMD5"] = self.fileMD5
        output["Author Name"] = self.authorName
        
        return output
        
    def getAllStringsA(self):
        strings = idautils.Strings(default_setup = False)
        allStrings = []
        strings.setup(strtypes=Strings.STR_C | Strings.STR_UNICODE, ignore_instructions = True, display_only_existing_strings = True,minlen=4)
        for string in strings:
            allStrings.append(str(string))
        return allStrings
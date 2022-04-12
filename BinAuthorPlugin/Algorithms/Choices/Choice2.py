from pymongo import MongoClient

from ida_nalt import get_root_filename, get_import_module_qty, enum_import_names, STRTYPE_C, STRTYPE_C_16
from idautils import GetInputFileMD5, Names, Heads, Strings
from idc import find_func_end, print_insn_mnem, get_operand_type, print_operand, get_operand_value
from ida_kernwin import action_handler_t, AST_ENABLE_ALWAYS


class Choice2Handler(action_handler_t):

    def __init__(self):
        action_handler_t.__init__(self)
        self.choice2 = Choice2()

    def activate(self, ctx):
        self.choice2.choice2()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class Choice2:

    def __init__(self):
        self.fileName = get_root_filename()
        self.fileMD5: bytes = GetInputFileMD5()
        self.authorName = self.fileName
        self.allStrings = {}
        self.subStrings = ["cout","endl","Xlength_error","cerr"]
        self.returns = {"ret":0,"retn":0}
        self.libraryFunctionNamesDict = {"printf":[0,0],"fprintf":[0,0],"cout":[0,0],"exit":[0,0],"fflush":[0,0],"endl":[0,0],"puts":[0,0],"Xlength_error":[0,0],"clock":[0,0],"cerr":[0,0]}#,"scanf":[0,0]}

        self.standardRegisters = {"eax":0,"ebx":0,"ecx":0,"edx":0,"esi":0,"edi":0}
        self.libraryFunctionNameEADict = {}
            
    def choice2(self):
        client = MongoClient('localhost', 27017)
        db = client.BinAuthor
        collection = db.Choice2
        
        numOfInstructions = 0
        printfNewline = [0,0]
        mainEA = 0
        #fileName = idc.ARGV[1]

        self.getAllStrings()
        for name in Names():
            if (str(name[1]).find("main") != -1) and (len(str(name[1])) <= 5):
                mainEA = name[0]

        numberOfImports = get_import_module_qty()

        for counter in range(0, numberOfImports):
            enum_import_names(counter, self.getImportedFunctions)

        for address in Heads(mainEA,find_func_end(mainEA)):
            numOfInstructions += 1


        currentInstruction = 0
        currentStackValue = ''
        numberOfCalls = 0
        previousInstructionEA = 0
        for address in Heads(mainEA,find_func_end(mainEA)):
            currentInstruction += 1
            if print_insn_mnem(address) == "push":
                previousInstructionEA = address
                currentStackValue = print_operand(address,0)
            elif print_insn_mnem(address) == "pop":
                currentStackValue = ''
            elif print_insn_mnem(address) == "mov":
                if print_operand(address,0) in self.standardRegisters.keys():
                    self.standardRegisters[print_operand(address,0)] = get_operand_value(address,1)
                    
            distanceFromEndOfFunction = int(numOfInstructions * (3/float(4)))
            if get_operand_type(address,0) == 1 and print_operand(address,0) in self.standardRegisters.keys():
                libraryInstruction = self.standardRegisters[print_operand(address,0)]
            else:
                libraryInstruction = get_operand_value(address,0)
            
            for string in self.subStrings:
                if string in print_operand(address,1) and currentInstruction >= distanceFromEndOfFunction:
                    self.libraryFunctionNamesDict[string][1] +=1
            
            if print_insn_mnem(address) == "call" and currentInstruction >= distanceFromEndOfFunction:
                numberOfCalls += 1
            
            if print_insn_mnem(address) in self.returns.keys() and currentInstruction >= distanceFromEndOfFunction:
                self.returns[print_insn_mnem(address)] += 1
                
            if print_insn_mnem(address) == "call" and libraryInstruction in self.libraryFunctionNameEADict.keys() and currentInstruction >= distanceFromEndOfFunction:
                if self.libraryFunctionNameEADict[libraryInstruction] == "exit":
                    if currentStackValue == "1":
                        self.libraryFunctionNamesDict[self.libraryFunctionNameEADict[libraryInstruction]][1] += 1
                else:
                    if "printf" in self.libraryFunctionNameEADict[libraryInstruction] and print_insn_mnem(previousInstructionEA) == "push":
                        locationOfPushValue = get_operand_value(previousInstructionEA,0)
                        
                        if locationOfPushValue in self.allStrings.keys():
                            if "\n" in self.allStrings[locationOfPushValue]:
                                printfNewline[0] += 1
                            else:
                                printfNewline[1] += 1
                            
                            
                    self.libraryFunctionNamesDict[self.libraryFunctionNameEADict[libraryInstruction]][1] += 1

        output = {"LibraryFunctions": {}}
        for libraryFunction in self.libraryFunctionNamesDict.keys():
            output["LibraryFunctions"][libraryFunction] = self.libraryFunctionNamesDict[libraryFunction][1]
        
        output["calls"] = numberOfCalls
        
        output["returns"] = self.returns
        output["printf with newline"] = printfNewline[0]
        output["printf without newline"] = printfNewline[1]
        output["FileName"] = self.fileName
        output["FileMD5"] = self.fileMD5
        output["Author Name"] = self.authorName
        collection.insert(output)
        
    def getChoice2(self):
        numOfInstructions = 0
        printfNewline = [0,0]
        mainEA = 0
        #fileName = idc.ARGV[1]

        self.getAllStrings()
        for name in Names():
            if (str(name[1]).find("main") != -1) and (len(str(name[1])) <= 5):
                mainEA = name[0]

        numberOfImports = get_import_module_qty()

        for counter in range(0, numberOfImports):
            enum_import_names(counter, self.getImportedFunctions)

        for address in Heads(mainEA,find_func_end(mainEA)):
            numOfInstructions += 1


        currentInstruction = 0
        currentStackValue = ''
        numberOfCalls = 0
        previousInstructionEA = 0
        for address in Heads(mainEA,find_func_end(mainEA)):
            currentInstruction += 1
            if print_insn_mnem(address) == "push":
                previousInstructionEA = address
                currentStackValue = print_operand(address,0)
            elif print_insn_mnem(address) == "pop":
                currentStackValue = ''
            elif print_insn_mnem(address) == "mov":
                if print_operand(address,0) in self.standardRegisters.keys():
                    self.standardRegisters[print_operand(address,0)] = get_operand_value(address,1)
                    
            distanceFromEndOfFunction = int(numOfInstructions * (3/float(4)))
            if get_operand_type(address,0) == 1 and print_operand(address,0) in self.standardRegisters.keys():
                libraryInstruction = self.standardRegisters[print_operand(address,0)]
            else:
                libraryInstruction = get_operand_value(address,0)
            
            for string in self.subStrings:
                if string in print_operand(address,1) and currentInstruction >= distanceFromEndOfFunction:
                    self.libraryFunctionNamesDict[string][1] +=1
            
            if print_insn_mnem(address) == "call" and currentInstruction >= distanceFromEndOfFunction:
                numberOfCalls += 1
            
            if print_insn_mnem(address) in self.returns.keys() and currentInstruction >= distanceFromEndOfFunction:
                self.returns[print_insn_mnem(address)] += 1
                
            if print_insn_mnem(address) == "call" and libraryInstruction in self.libraryFunctionNameEADict.keys() and currentInstruction >= distanceFromEndOfFunction:
                if self.libraryFunctionNameEADict[libraryInstruction] == "exit":
                    if currentStackValue == "1":
                        self.libraryFunctionNamesDict[self.libraryFunctionNameEADict[libraryInstruction]][1] += 1
                else:
                    if "printf" in self.libraryFunctionNameEADict[libraryInstruction] and print_insn_mnem(previousInstructionEA) == "push":
                        locationOfPushValue = get_operand_value(previousInstructionEA,0)
                        
                        if locationOfPushValue in self.allStrings.keys():
                            if "\n" in self.allStrings[locationOfPushValue]:
                                printfNewline[0] += 1
                            else:
                                printfNewline[1] += 1
                            
                            
                    self.libraryFunctionNamesDict[self.libraryFunctionNameEADict[libraryInstruction]][1] += 1

        output = {"LibraryFunctions": {}}
        for libraryFunction in self.libraryFunctionNamesDict.keys():
            output["LibraryFunctions"][libraryFunction] = self.libraryFunctionNamesDict[libraryFunction][1]
        
        output["calls"] = numberOfCalls
        
        output["returns"] = self.returns
        output["printf with newline"] = printfNewline[0]
        output["printf without newline"] = printfNewline[1]
        output["FileName"] = self.fileName
        output["FileMD5"] = self.fileMD5
        output["Author Name"] = self.authorName
        return output

    def getAllStrings(self):
        strings = Strings(default_setup=False)
        strings.setup(
            strtypes=STRTYPE_C | STRTYPE_C_16, ignore_instructions=True, display_only_existing_strings=True, minlen=1
        )
        for string in strings:
            self.allStrings[string.ea] = str(string)

    def getImportedFunctions(self,ea, libraryFunctionName, ord):
        if libraryFunctionName in self.libraryFunctionNamesDict.keys():
            self.libraryFunctionNamesDict[libraryFunctionName][0] = ea
            self.libraryFunctionNameEADict[ea] = libraryFunctionName
        
        if "cout" in libraryFunctionName:
            self.libraryFunctionNamesDict["cout"][0] = ea
            self.libraryFunctionNameEADict[ea] = "cout"
        
        if "endl" in libraryFunctionName:
            self.libraryFunctionNamesDict["endl"][0] = ea
            self.libraryFunctionNameEADict[ea] = "endl"
        
        if "Xlength_error" in libraryFunctionName:
            self.libraryFunctionNamesDict["Xlength_error"][0] = ea
            self.libraryFunctionNameEADict[ea] = "Xlength_error"
        
        if "cerr" in libraryFunctionName:
            self.libraryFunctionNamesDict["cerr"][0] = ea
            self.libraryFunctionNameEADict[ea] = "cerr"
        return True
        


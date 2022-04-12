from simhash import Simhash
from pymongo.collection import Collection

from ida_nalt import get_root_filename
from idautils import GetInputFileMD5, Heads, Functions
from idc import print_insn_mnem, get_operand_type, print_operand
from ida_funcs import get_func, get_func_name
from ida_gdl import FlowChart
from ida_kernwin import action_handler_t, AST_ENABLE_ALWAYS

from Database.mongodb import MongoDB, Collections
from BinAuthorPlugin.ExternalScripts.minhash import minhash


class Choice18Handler(action_handler_t):

    def __init__(self):
        action_handler_t.__init__(self)
        self.choice18 = Choice18()

    def activate(self, ctx):
        self.choice18.choice18()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class Choice18:

    def __init__(self):
        self.fileName = get_root_filename()
        self.fileMD5: bytes = GetInputFileMD5()
        self.authorName = self.fileName
        self.collection: Collection = MongoDB(Collections.choice18).collection

        self.functionAddresstoRealFunctionName = {}
        self.functionRegisterChains = {}
        self.finalOutput = ''
        self.finalOutputFunctionLevel = ''
        self.simhashList = []
        self.registerChainMinhash = []
        self.blocks = []

    def createRegisterChain(self,p,ea):
        f = FlowChart(get_func(ea))
        
        functionName = get_func_name(ea)
        client = MongoClient('localhost', 27017)
        db = client.BinAuthor
        collection = db.Choice18
        
        if get_func_name(ea) not in self.functionRegisterChains.keys():
            self.functionRegisterChains[get_func_name(ea)] = {}
        for block in f:
            if p:
                registerChain = {}
                for address in Heads(block.startEA,block.endEA):
                    if get_operand_type(address, 0) == 1 and print_operand(address, 0) != "":
                        if print_operand(address, 0) not in self.functionRegisterChains[get_func_name(ea)].keys():
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 0)] = [print_insn_mnem(address)]
                        else:
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 0)].append(print_insn_mnem(address))
                            
                        if print_operand(address, 0) not in registerChain.keys():
                            registerChain[print_operand(address, 0)] = [print_insn_mnem(address)]
                        else:
                            registerChain[print_operand(address, 0)].append(print_insn_mnem(address))
                    if get_operand_type(address, 1) == 1  and print_operand(address, 1) != "":
                        if print_operand(address, 1) not in self.functionRegisterChains[get_func_name(ea)].keys():
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 1)] = [print_insn_mnem(address)]
                        else:
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 1)].append(print_insn_mnem(address))
                        
                        if print_operand(address, 1) not in registerChain.keys():
                            registerChain[print_operand(address, 1)] = [print_insn_mnem(address)]
                        else:
                            registerChain[print_operand(address, 1)].append(print_insn_mnem(address))
                for register in registerChain.keys():
                    fingerPrint = str(register)
                    functionMinhashes = {}
                    functionMinhashes["FunctionName"] = functionName
                    functionMinhashes["FileName"] = self.fileName
                    functionMinhashes["FileMD5"] = self.fileMD5
                    functionMinhashes["Author Name"] = self.authorName
                    functionMinhashes["BlockStartEA"] = block.startEA
                    functionMinhashes["register"] = register
                    functionMinhashes["registerChain"] = registerChain[register]
                    counter = 0
                    for instruction in registerChain[register]:
                        fingerPrint += " " + str(instruction)
                        counter += 1
                        
                    functionMinhashes["SimHashSignature"] = str(Simhash(fingerPrint).value)

                    self.simhashList.append([counter,Simhash(fingerPrint).value])
                    if len(fingerPrint.split(" ")) >= 6:
                        self.registerChainMinhash.append([fingerPrint,minhash.minHash(minhash.createShingles(fingerPrint))])
                        functionMinhashes["MinHashSignature"] = minhash.minHash(minhash.createShingles(fingerPrint))
                        self.collection.insert_one(functionMinhashes)
                    else:
                        self.registerChainMinhash.append([fingerPrint,])
                        
    def createRegisterChainA(self,p,ea):
        f = FlowChart(get_func(ea))
        
        functionName = get_func_name(ea)
        
        functions = []
        
        if get_func_name(ea) not in self.functionRegisterChains.keys():
            self.functionRegisterChains[get_func_name(ea)] = {}
        for block in f:
            if p:
                registerChain = {}
                for address in Heads(block.startEA,block.endEA):
                    if get_operand_type(address, 0) == 1 and print_operand(address, 0) != "":
                        if print_operand(address, 0) not in self.functionRegisterChains[get_func_name(ea)].keys():
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 0)] = [print_insn_mnem(address)]
                        else:
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 0)].append(print_insn_mnem(address))
                            
                        if print_operand(address, 0) not in registerChain.keys():
                            registerChain[print_operand(address, 0)] = [print_insn_mnem(address)]
                        else:
                            registerChain[print_operand(address, 0)].append(print_insn_mnem(address))
                    if get_operand_type(address, 1) == 1  and print_operand(address, 1) != "":
                        if print_operand(address, 1) not in self.functionRegisterChains[get_func_name(ea)].keys():
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 1)] = [print_insn_mnem(address)]
                        else:
                            self.functionRegisterChains[get_func_name(ea)][print_operand(address, 1)].append(print_insn_mnem(address))
                        
                        if print_operand(address, 1) not in registerChain.keys():
                            registerChain[print_operand(address, 1)] = [print_insn_mnem(address)]
                        else:
                            registerChain[print_operand(address, 1)].append(print_insn_mnem(address))
                for register in registerChain.keys():
                    fingerPrint = str(register)
                    functionMinhashes = {}
                    functionMinhashes["FunctionName"] = functionName
                    functionMinhashes["FileName"] = self.fileName
                    functionMinhashes["FileMD5"] = self.fileMD5
                    functionMinhashes["Author Name"] = self.authorName
                    functionMinhashes["BlockStartEA"] = block.startEA
                    functionMinhashes["register"] = register
                    functionMinhashes["registerChain"] = registerChain[register]
                    counter = 0
                    for instruction in registerChain[register]:
                        fingerPrint += " " + str(instruction)
                        counter += 1
                        
                    functionMinhashes["SimHashSignature"] = str(Simhash(fingerPrint).value)

                    self.simhashList.append([counter,Simhash(fingerPrint).value])
                    if len(fingerPrint.split(" ")) >= 6:
                        self.registerChainMinhash.append([fingerPrint,minhash.minHash(minhash.createShingles(fingerPrint))])
                        functionMinhashes["MinHashSignature"] = minhash.minHash(minhash.createShingles(fingerPrint))
                        functions.append(functionMinhashes)
                    else:
                        self.registerChainMinhash.append([fingerPrint,])
        return functions

    def choice18(self):
        for function in Functions():
            self.functionAddresstoRealFunctionName[function] = get_func_name(function)
            self.createRegisterChain(True,function)
            
    def choice18A(self):
        functions = []
        for function in Functions():
            self.functionAddresstoRealFunctionName[function] = get_func_name(function)
            functions.append(self.createRegisterChainA(True,function))
            
        return functions
   
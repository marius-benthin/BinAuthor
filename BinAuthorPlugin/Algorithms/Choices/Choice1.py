from math import log
from pymongo import MongoClient

from ida_idaapi import BADADDR
from ida_nalt import get_root_filename
from idautils import GetInputFileMD5, Names, Heads
from idc import find_func_end, print_insn_mnem, next_head, get_operand_type, print_operand
from ida_kernwin import action_handler_t, AST_ENABLE_ALWAYS




class Choice1Handler(action_handler_t):

    def __init__(self):
        action_handler_t.__init__(self)
        self.choice1 = Choice1()

    def activate(self, ctx):
        self.choice1.choice1()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class Choice1:

    def __init__(self):
        self.fileName: str = get_root_filename()
        self.fileMD5: bytes = GetInputFileMD5()
        self.authorName = self.fileName
        
    def choice1(self):
        client = MongoClient('localhost', 27017)
        db = client.BinAuthor
        collection = db.Choice1

        #fileName = get_root_filename()
        #fileMD5 = GetInputFileMD5()

        mainEA = 0

        totalInstructions = 0
        instructionCounts = {"jmp":0,"cmp":0,"test":0,"mov":0,"call":0,"lea":0,"push":0,"indirect_call" : 0, "reg_used":0} 
        registerCounts = {}

        output = {}

        #authorName = idc.ARGV[1]

        for name in Names():
            if (str(name[1]).find("main") != -1) and (len(str(name[1])) <= 5):
                mainEA = name[0]

        currentea = mainEA
        while currentea != BADADDR and currentea < find_func_end(mainEA):
            currentInstruction = print_insn_mnem(currentea)
            if currentInstruction in instructionCounts.keys():
                instructionCounts[currentInstruction] += 1
            totalInstructions += 1
            currentea = next_head(currentea)

        for item in Heads(mainEA,find_func_end(mainEA)):
            #print(hex(item) + ":" + print_insn_mnem(item) + "\t" + str(get_operand_type(item,0)) + "\t" + str(get_operand_type(item,1)))
            if "call" == print_insn_mnem(item) and get_operand_type(item,0) == 1:
                instructionCounts["indirect_call"] += 1
            if get_operand_type(item,0) == 1:
                instructionCounts["reg_used"] += 1
                
                register = print_operand(item,0)
                if register not in registerCounts.keys():
                    registerCounts[register] = 1
                else:
                    registerCounts[register] += 1
            if get_operand_type(item,1) == 1:
                instructionCounts["reg_used"] += 1
                
                register = print_operand(item,1)
                if register not in registerCounts.keys():
                    registerCounts[register] = 1
                else:
                    registerCounts[register] += 1
                
        output["Total"] = totalInstructions
        output["push"] = instructionCounts["push"]
        output["call"] = instructionCounts["call"]
        output["indirect calls"] = instructionCounts["indirect_call"]
        output["regs used"] = instructionCounts["reg_used"]

        if float(totalInstructions) != 0 :
            output["ln(num push/length)"] = log(instructionCounts["push"]/float(totalInstructions))
            output["ln(num call/length)"] = log(instructionCounts["call"]/float(totalInstructions))
        else:
            output["ln(num push/length)"] = "infinity"
            output["ln(num call/length)"] = "infinity"
        if float(totalInstructions) != 0:
            if (instructionCounts["indirect_call"]/float(totalInstructions)) != 0 and (instructionCounts["reg_used"]/float(totalInstructions)) != 0:
                output["ln(num Indirect call/length)"] = log(instructionCounts["indirect_call"]/float(totalInstructions))
                output["ln(num reg used/length)"] = log(instructionCounts["reg_used"]/float(totalInstructions))
            elif (instructionCounts["indirect_call"]/float(totalInstructions)) == 0:
                output["ln(num Indirect call/length)"] = "infinity"
                output["ln(num reg used/length)"] = log(instructionCounts["reg_used"]/float(totalInstructions))
            elif (instructionCounts["reg_used"]/float(totalInstructions)) == 0:
                output["ln(num Indirect call/length)"] = log(instructionCounts["indirect_call"]/float(totalInstructions))
                output["ln(num reg used/length)"] = "infinity"
        else:
            output["ln(num Indirect call/length)"] = "infinity"
            output["ln(num reg used/length)"] = "infinity"

        if float(instructionCounts["lea"]) != 0 and (instructionCounts["push"]/float(instructionCounts["lea"])) != 0:
            output["ln(num push/num lea)"] = log(instructionCounts["push"]/float(instructionCounts["lea"]))
        else:
            output["ln(num push/num lea)"] = "infinity"

        if float(instructionCounts["test"]) != 0 and (instructionCounts["cmp"]/float(instructionCounts["test"])) != 0:     
            output["ln(num cmp/num test)"] = log(instructionCounts["cmp"]/float(instructionCounts["test"]))
        else:
            output["ln(num cmp/num test)"] = "infinity"

        if float(instructionCounts["push"]) != 0 and (instructionCounts["mov"]/float(instructionCounts["push"])) != 0:
            output["ln(num mov/num push)"] = log(instructionCounts["mov"]/float(instructionCounts["push"]))
        else:
            output["ln(num mov/num push)"] = "infinity" 
        if float(instructionCounts["lea"]) != 0 and (instructionCounts["jmp"]/float(instructionCounts["lea"])) != 0:
            output["ln(num jmp/num lea)"] = log(instructionCounts["jmp"]/float(instructionCounts["lea"]))
        else:
            output["ln(num jmp/num lea)"] = "infinity"

        if float(instructionCounts["call"]) != 0 and (instructionCounts["indirect_call"]/float(instructionCounts["call"])) != 0:     
            output["ln(num indirect call/num call)"] = log(instructionCounts["indirect_call"]/float(instructionCounts["call"]))
        else:
            output["ln(num indirect call/num call)"] = "infinity"

        if float(registerCounts["ecx"]) != 0:    
            output["ln(num eax/num ecx)"] = log(registerCounts["eax"]/float(registerCounts["ecx"]))
        else:
            output["ln(num eax/num ecx)"] = "infinity"
        if "esi" in registerCounts.keys() and "edi" in registerCounts.keys():
            if float(registerCounts["edi"]) != 0 and (registerCounts["esi"]/float(registerCounts["edi"])) != 0:
                output["ln(num esi/num edi)"] = log(registerCounts["esi"]/float(registerCounts["edi"]))
            else:
                output["ln(num esi/num edi)"] = "infinity"
        else:
            output["ln(num esi/num edi)"] = "infinity"

        document = {"General": output}

        if float(instructionCounts["lea"]) != 0:
            if (instructionCounts["push"]/float(instructionCounts["lea"])) != 0:
                feature1 = log(instructionCounts["push"]/float(instructionCounts["lea"]))
            else:
                feature1 = -1
            if (instructionCounts["jmp"]/float(instructionCounts["lea"])) != 0:
                feature2 = log(instructionCounts["jmp"]/float(instructionCounts["lea"]))
            else:
                feature2 = -1
        else:
            feature1 = -1
            feature2 = -1

        if float(instructionCounts["push"]) != 0 and (instructionCounts["mov"]/float(instructionCounts["push"])) != 0:
            feature3 = log(instructionCounts["mov"]/float(instructionCounts["push"]))
        else:
            feature3 = -1

        if float(instructionCounts["call"]) != 0 and (instructionCounts["indirect_call"]/float(instructionCounts["call"])) != 0:
            feature4 = log(instructionCounts["indirect_call"]/float(instructionCounts["call"]))
        else:
            feature4 = -1

        if float(instructionCounts["test"]) != 0 and (instructionCounts["cmp"]/float(instructionCounts["test"])) != 0:
            feature5 = log(instructionCounts["cmp"]/float(instructionCounts["test"]))
        else:
            feature5 = -1
            
        if float(totalInstructions) != 0:
            if (instructionCounts["reg_used"]/float(totalInstructions)) != 0:
                feature6 = log(instructionCounts["reg_used"]/float(totalInstructions))
            else:
                feature6 = -1
            if (instructionCounts["push"]/float(totalInstructions)) != 0:
                feature7 = log(instructionCounts["push"]/float(totalInstructions))
            else:
                feature7 = -1
            if (instructionCounts["call"]/float(totalInstructions)) != 0:
                feature8 = log(instructionCounts["call"]/float(totalInstructions))
            else:
                feature8 = -1
            if (instructionCounts["indirect_call"]/float(totalInstructions)) != 0:
                feature9 = log(instructionCounts["indirect_call"]/float(totalInstructions))
            else:
                feature9 = -1
        else:
            feature6 = -1
            feature7 = -1
            feature8 = -1
            feature9 = -1

        if float(registerCounts["ecx"]) != 0:
            feature10 = log(registerCounts["eax"]/float(registerCounts["ecx"]))
        else:
            feature10 = -1

        if "edi" in registerCounts.keys():
            if float(registerCounts["edi"]) != 0:
                feature11 = log(registerCounts["esi"]/float(registerCounts["edi"]))
            else:
                feature11 = -1
        else:
            feature11 = -2
        featureList = [feature1,\
                       feature3,\
                       feature4,\
                       feature5,\
                       feature6,\
                       feature10,\
                       feature11,\
                       feature2,\
                       feature7,\
                       feature8,\
                       feature9]
        document["features"] = featureList
        document["FileName"] = self.fileName
        document["FileMD5"] = self.fileMD5
        document["Author Name"] = self.authorName
        collection.insert(document)
        
    def getChoice1(self):
        mainEA = 0

        totalInstructions = 0
        instructionCounts = {"jmp":0,"cmp":0,"test":0,"mov":0,"call":0,"lea":0,"push":0,"indirect_call" : 0, "reg_used":0} 
        registerCounts = {}

        output = {}

        for name in Names():
            if (str(name[1]).find("main") != -1) and (len(str(name[1])) <= 5):
                mainEA = name[0]

        currentea = mainEA
        while currentea != BADADDR and currentea < find_func_end(mainEA):
            currentInstruction = print_insn_mnem(currentea)
            if currentInstruction in instructionCounts.keys():
                instructionCounts[currentInstruction] += 1
            totalInstructions += 1
            currentea = next_head(currentea)

        for item in Heads(mainEA,find_func_end(mainEA)):
            #print(hex(item) + ":" + print_insn_mnem(item) + "\t" + str(get_operand_type(item,0)) + "\t" + str(get_operand_type(item,1)))
            if "call" == print_insn_mnem(item) and get_operand_type(item,0) == 1:
                instructionCounts["indirect_call"] += 1
            if get_operand_type(item,0) == 1:
                instructionCounts["reg_used"] += 1
                
                register = print_operand(item,0)
                if register not in registerCounts.keys():
                    registerCounts[register] = 1
                else:
                    registerCounts[register] += 1
            if get_operand_type(item,1) == 1:
                instructionCounts["reg_used"] += 1
                
                register = print_operand(item,1)
                if register not in registerCounts.keys():
                    registerCounts[register] = 1
                else:
                    registerCounts[register] += 1
                
        output["Total"] = totalInstructions
        output["push"] = instructionCounts["push"]
        output["call"] = instructionCounts["call"]
        output["indirect calls"] = instructionCounts["indirect_call"]
        output["regs used"] = instructionCounts["reg_used"]

        if float(totalInstructions) != 0 :
            output["ln(num push/length)"] = log(instructionCounts["push"]/float(totalInstructions))
            output["ln(num call/length)"] = log(instructionCounts["call"]/float(totalInstructions))
        else:
            output["ln(num push/length)"] = "infinity"
            output["ln(num call/length)"] = "infinity"
        if float(totalInstructions) != 0:
            if (instructionCounts["indirect_call"]/float(totalInstructions)) != 0 and (instructionCounts["reg_used"]/float(totalInstructions)) != 0:
                output["ln(num Indirect call/length)"] = log(instructionCounts["indirect_call"]/float(totalInstructions))
                output["ln(num reg used/length)"] = log(instructionCounts["reg_used"]/float(totalInstructions))
            elif (instructionCounts["indirect_call"]/float(totalInstructions)) == 0:
                output["ln(num Indirect call/length)"] = "infinity"
                output["ln(num reg used/length)"] = log(instructionCounts["reg_used"]/float(totalInstructions))
            elif (instructionCounts["reg_used"]/float(totalInstructions)) == 0:
                output["ln(num Indirect call/length)"] = log(instructionCounts["indirect_call"]/float(totalInstructions))
                output["ln(num reg used/length)"] = "infinity"
        else:
            output["ln(num Indirect call/length)"] = "infinity"
            output["ln(num reg used/length)"] = "infinity"

        if float(instructionCounts["lea"]) != 0 and (instructionCounts["push"]/float(instructionCounts["lea"])) != 0:
            output["ln(num push/num lea)"] = log(instructionCounts["push"]/float(instructionCounts["lea"]))
        else:
            output["ln(num push/num lea)"] = "infinity"

        if float(instructionCounts["test"]) != 0 and (instructionCounts["cmp"]/float(instructionCounts["test"])) != 0:     
            output["ln(num cmp/num test)"] = log(instructionCounts["cmp"]/float(instructionCounts["test"]))
        else:
            output["ln(num cmp/num test)"] = "infinity"

        if float(instructionCounts["push"]) != 0 and (instructionCounts["mov"]/float(instructionCounts["push"])) != 0:
            output["ln(num mov/num push)"] = log(instructionCounts["mov"]/float(instructionCounts["push"]))
        else:
            output["ln(num mov/num push)"] = "infinity" 
        if float(instructionCounts["lea"]) != 0 and (instructionCounts["jmp"]/float(instructionCounts["lea"])) != 0:
            output["ln(num jmp/num lea)"] = log(instructionCounts["jmp"]/float(instructionCounts["lea"]))
        else:
            output["ln(num jmp/num lea)"] = "infinity"

        if float(instructionCounts["call"]) != 0 and (instructionCounts["indirect_call"]/float(instructionCounts["call"])) != 0:     
            output["ln(num indirect call/num call)"] = log(instructionCounts["indirect_call"]/float(instructionCounts["call"]))
        else:
            output["ln(num indirect call/num call)"] = "infinity"

        if float(registerCounts["ecx"]) != 0:    
            output["ln(num eax/num ecx)"] = log(registerCounts["eax"]/float(registerCounts["ecx"]))
        else:
            output["ln(num eax/num ecx)"] = "infinity"
        if "esi" in registerCounts.keys() and "edi" in registerCounts.keys():
            if float(registerCounts["edi"]) != 0 and (registerCounts["esi"]/float(registerCounts["edi"])) != 0:
                output["ln(num esi/num edi)"] = log(registerCounts["esi"]/float(registerCounts["edi"]))
            else:
                output["ln(num esi/num edi)"] = "infinity"
        else:
            output["ln(num esi/num edi)"] = "infinity"

        document = {"General": output}

        if float(instructionCounts["lea"]) != 0:
            if (instructionCounts["push"]/float(instructionCounts["lea"])) != 0:
                feature1 = log(instructionCounts["push"]/float(instructionCounts["lea"]))
            else:
                feature1 = -1
            if (instructionCounts["jmp"]/float(instructionCounts["lea"])) != 0:
                feature2 = log(instructionCounts["jmp"]/float(instructionCounts["lea"]))
            else:
                feature2 = -1
        else:
            feature1 = -1
            feature2 = -1

        if float(instructionCounts["push"]) != 0 and (instructionCounts["mov"]/float(instructionCounts["push"])) != 0:
            feature3 = log(instructionCounts["mov"]/float(instructionCounts["push"]))
        else:
            feature3 = -1

        if float(instructionCounts["call"]) != 0 and (instructionCounts["indirect_call"]/float(instructionCounts["call"])) != 0:
            feature4 = log(instructionCounts["indirect_call"]/float(instructionCounts["call"]))
        else:
            feature4 = -1

        if float(instructionCounts["test"]) != 0 and (instructionCounts["cmp"]/float(instructionCounts["test"])) != 0:
            feature5 = log(instructionCounts["cmp"]/float(instructionCounts["test"]))
        else:
            feature5 = -1
            
        if float(totalInstructions) != 0:
            if (instructionCounts["reg_used"]/float(totalInstructions)) != 0:
                feature6 = log(instructionCounts["reg_used"]/float(totalInstructions))
            else:
                feature6 = -1
            if (instructionCounts["push"]/float(totalInstructions)) != 0:
                feature7 = log(instructionCounts["push"]/float(totalInstructions))
            else:
                feature7 = -1
            if (instructionCounts["call"]/float(totalInstructions)) != 0:
                feature8 = log(instructionCounts["call"]/float(totalInstructions))
            else:
                feature8 = -1
            if (instructionCounts["indirect_call"]/float(totalInstructions)) != 0:
                feature9 = log(instructionCounts["indirect_call"]/float(totalInstructions))
            else:
                feature9 = -1
        else:
            feature6 = -1
            feature7 = -1
            feature8 = -1
            feature9 = -1

        if float(registerCounts["ecx"]) != 0:
            feature10 = log(registerCounts["eax"]/float(registerCounts["ecx"]))
        else:
            feature10 = -1

        if "edi" in registerCounts.keys():
            if float(registerCounts["edi"]) != 0:
                feature11 = log(registerCounts["esi"]/float(registerCounts["edi"]))
            else:
                feature11 = -1
        else:
            feature11 = -2
        featureList = [feature1,\
                       feature3,\
                       feature4,\
                       feature5,\
                       feature6,\
                       feature10,\
                       feature11,\
                       feature2,\
                       feature7,\
                       feature8,\
                       feature9]
        document["features"] = featureList
        document["FileName"] = self.fileName
        document["FileMD5"] = self.fileMD5
        document["Author Name"] = self.authorName
        return document
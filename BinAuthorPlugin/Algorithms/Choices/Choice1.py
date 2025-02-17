from math import log
from pymongo.collection import Collection

from ida_idaapi import BADADDR
from ida_nalt import get_root_filename, retrieve_input_file_sha256
from idautils import Names, Heads
from idc import find_func_end, print_insn_mnem, next_head, get_operand_type, print_operand
from ida_kernwin import action_handler_t, AST_ENABLE_ALWAYS


from Database.mongodb import MongoDB, Collections


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

    def __init__(self, authorName: str = None):
        self.fileName: str = get_root_filename()
        self.fileSHA256: str = retrieve_input_file_sha256().hex()
        # use ARGV[1] if it was passed with authorName else fileName
        self.authorName: str = self.fileName if authorName is None else authorName
        self.collection_choice1: Collection = MongoDB(Collections.choice1).collection

    def choice1(self):
        document = self.getChoice1()
        self.collection_choice1.insert_one(document)

    def getChoice1(self):
        mainEA = 0

        totalInstructions = 0
        instructionCounts = {
            "jmp": 0,
            "cmp": 0,
            "test": 0,
            "mov": 0,
            "call": 0,
            "lea": 0,
            "push": 0,
            "indirect_call": 0,
            "reg_used": 0
        }
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

        for item in Heads(mainEA, find_func_end(mainEA)):
            if "call" == print_insn_mnem(item) and get_operand_type(item, 0) == 1:
                instructionCounts["indirect_call"] += 1
            if get_operand_type(item, 0) == 1:
                instructionCounts["reg_used"] += 1

                register = print_operand(item, 0)
                if register not in registerCounts.keys():
                    registerCounts[register] = 1
                else:
                    registerCounts[register] += 1
            if get_operand_type(item, 1) == 1:
                instructionCounts["reg_used"] += 1

                register = print_operand(item, 1)
                if register not in registerCounts.keys():
                    registerCounts[register] = 1
                else:
                    registerCounts[register] += 1

        output["Total"] = totalInstructions
        output["push"] = instructionCounts["push"]
        output["call"] = instructionCounts["call"]
        output["indirect calls"] = instructionCounts["indirect_call"]
        output["regs used"] = instructionCounts["reg_used"]

        output["ln(num push/length)"] = "infinity"
        output["ln(num call/length)"] = "infinity"
        output["ln(num Indirect call/length)"] = "infinity"
        output["ln(num reg used/length)"] = "infinity"
        output["ln(num push/num lea)"] = "infinity"
        output["ln(num cmp/num test)"] = "infinity"
        output["ln(num mov/num push)"] = "infinity"
        output["ln(num jmp/num lea)"] = "infinity"
        output["ln(num indirect call/num call)"] = "infinity"
        output["ln(num eax/num ecx)"] = "infinity"
        output["ln(num esi/num edi)"] = "infinity"

        totalInstructions = float(totalInstructions)
        if totalInstructions != 0:
            if instructionCounts["push"] != 0:
                output["ln(num push/length)"] = log(instructionCounts["push"] / totalInstructions)
            if instructionCounts["call"] != 0:
                output["ln(num call/length)"] = log(instructionCounts["call"] / totalInstructions)
            if instructionCounts["indirect_call"] != 0:
                output["ln(num Indirect call/length)"] = log(instructionCounts["indirect_call"] / totalInstructions)
            if instructionCounts["reg_used"] != 0:
                output["ln(num reg used/length)"] = log(instructionCounts["reg_used"] / totalInstructions)

        if float(instructionCounts["lea"]) != 0 and instructionCounts["push"] != 0:
            output["ln(num push/num lea)"] = log(instructionCounts["push"] / float(instructionCounts["lea"]))
        if float(instructionCounts["test"]) != 0 and instructionCounts["cmp"] != 0:
            output["ln(num cmp/num test)"] = log(instructionCounts["cmp"] / float(instructionCounts["test"]))
        if float(instructionCounts["push"]) != 0 and instructionCounts["mov"] != 0:
            output["ln(num mov/num push)"] = log(instructionCounts["mov"] / float(instructionCounts["push"]))
        if float(instructionCounts["lea"]) != 0 and instructionCounts["jmp"] != 0:
            output["ln(num jmp/num lea)"] = log(instructionCounts["jmp"] / float(instructionCounts["lea"]))
        if float(instructionCounts["call"]) != 0 and instructionCounts["indirect_call"] != 0:
            output["ln(num indirect call/num call)"] = log(instructionCounts["indirect_call"] / float(instructionCounts["call"]))

        if "eax" in registerCounts.keys() and "ecx" in registerCounts.keys():
            if float(registerCounts["ecx"]) != 0 and registerCounts["eax"] != 0:
                output["ln(num eax/num ecx)"] = log(registerCounts["eax"] / float(registerCounts["ecx"]))

        if "esi" in registerCounts.keys() and "edi" in registerCounts.keys():
            if float(registerCounts["edi"]) != 0 and registerCounts["esi"] != 0:
                output["ln(num esi/num edi)"] = log(registerCounts["esi"] / float(registerCounts["edi"]))

        document = {"General": output}

        feature1 = -1
        feature2 = -1
        feature3 = -1
        feature4 = -1
        feature5 = -1
        feature6 = -1
        feature7 = -1
        feature8 = -1
        feature9 = -1
        feature10 = -1
        feature11 = -2

        if float(instructionCounts["lea"]) != 0:
            if instructionCounts["push"] != 0:
                feature1 = log(instructionCounts["push"] / float(instructionCounts["lea"]))
            if instructionCounts["jmp"] != 0:
                feature2 = log(instructionCounts["jmp"] / float(instructionCounts["lea"]))

        if float(instructionCounts["push"]) != 0 and instructionCounts["mov"] != 0:
            feature3 = log(instructionCounts["mov"] / float(instructionCounts["push"]))

        if float(instructionCounts["call"]) != 0 and instructionCounts["indirect_call"] != 0:
            feature4 = log(instructionCounts["indirect_call"] / float(instructionCounts["call"]))

        if float(instructionCounts["test"]) != 0 and instructionCounts["cmp"] != 0:
            feature5 = log(instructionCounts["cmp"] / float(instructionCounts["test"]))

        if totalInstructions != 0:
            if instructionCounts["reg_used"] != 0:
                feature6 = log(instructionCounts["reg_used"] / totalInstructions)
            if instructionCounts["push"] != 0:
                feature7 = log(instructionCounts["push"] / totalInstructions)
            if instructionCounts["call"] != 0:
                feature8 = log(instructionCounts["call"] / totalInstructions)
            if instructionCounts["indirect_call"] != 0:
                feature9 = log(instructionCounts["indirect_call"] / totalInstructions)

        if "eax" in registerCounts.keys() and "ecx" in registerCounts.keys():
            if float(registerCounts["ecx"]) != 0 and registerCounts["eax"] != 0:
                feature10 = log(registerCounts["eax"] / float(registerCounts["ecx"]))
        else:
            feature10 = -2

        if "edi" in registerCounts.keys() and "esi" in registerCounts.keys():
            if float(registerCounts["edi"]) != 0 and registerCounts["esi"] != 0:
                feature11 = log(registerCounts["esi"] / float(registerCounts["edi"]))
        else:
            feature11 = -2

        featureList = [
            feature1, feature3, feature4, feature5, feature6, feature10, feature11, feature2, feature7, feature8,
            feature9
        ]

        document["features"] = featureList
        document["FileName"] = self.fileName
        document["FileSHA256"] = self.fileSHA256
        document["Author Name"] = self.authorName
        return document

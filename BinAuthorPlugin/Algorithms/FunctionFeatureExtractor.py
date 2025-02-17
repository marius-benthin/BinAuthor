from hashlib import md5
from copy import deepcopy
from datetime import datetime
from pymongo.collection import Collection

from ida_idaapi import BADADDR
from ida_nalt import get_root_filename, retrieve_input_file_sha256
from idautils import Functions
from idc import next_head, print_insn_mnem, find_func_end, get_segm_start, get_segm_end
from ida_funcs import get_func_name
from ida_ida import inf_get_min_ea

from config import Config
from Database.mongodb import MongoDB, Collections


class FeatureExtractor:

    def __init__(self):

        _config: Config = Config()

        self.collection_functions: Collection = MongoDB(Collections.functions).collection

        self.instructionList = _config.bin_author_path / "Features" / "InstructionList.txt"
        self.groupList = _config.bin_author_path / "Features" / "InstructionGroups.txt"

        self.instructions = {}
        self.groups = {}

        self.fileName: str = get_root_filename()
        self.fileSHA256: str = retrieve_input_file_sha256().hex()
        self.dateAnalyzed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # load instructions into dictionary
    def loadInstructionList(self):
        for line in open(self.instructionList, "r"):
            self.instructions[line.replace(" ", "").replace("\n", "")] = 0

    def loadInstructionGroups(self):
        currentGroup = ''
        for line in open(self.groupList, "r"):
            if line.find("[") != -1:
                currentGroup = line.replace("[", '').replace("]", '').replace('\n', '')
                self.groups[currentGroup] = [{}, 0]
            else:
                self.groups[currentGroup][0][line.replace('\n', '')] = 0

    def writeInstructionFeatures(self, instructions, total, functionInstructions, file):
        oldFileName = file
        bulkInsert = []
        for instruction in instructions.keys():
            mean = (functionInstructions[instruction] / float(total))
            variance = ((functionInstructions[instruction] - mean) ** 2 / total)
            if functionInstructions[instruction] > 0:
                hashFunction = md5()
                hashFunction.update((self.fileSHA256 + "," + file + "," + "instructions," + instruction + "," + str(
                    functionInstructions[instruction]) + "," + str(mean) + "," + str(variance)).encode('utf-8'))
                bulkInsert.append(
                    {"binaryFileName": self.fileName, "SHA256": self.fileSHA256, "Date Analyzed": self.dateAnalyzed,
                     "function": oldFileName, "type": "instructions", "hash": hashFunction.hexdigest(),
                     "instruction": instruction, "instructionCount": functionInstructions[instruction], "mean": mean,
                     "variance": variance})
        try:
            self.collection_functions.insert_many(bulkInsert)
        except Exception:
            pass

    """
    def getInstructionFeatures(self, instructions, total, functionInstructions, file):
        oldFileName = file
        bulkInsert = []
        for instruction in instructions.keys():
            mean = (functionInstructions[instruction]/float(total))
            variance = ((functionInstructions[instruction] - mean)**2/total)
            if functionInstructions[instruction] > 0:
                hashFunction = md5()
                hashFunction.update((
                    self.fileSHA256 + "," + file + "," + "instructions," + instruction + "," + 
                    str(functionInstructions[instruction]) + "," + str(mean) + "," + str(variance)).encode('utf-8')
                )
                bulkInsert.append(
                    {
                        "binaryFileName": self.fileName,
                        "SHA256": self.fileSHA256,
                        "Date Analyzed": self.dateAnalyzed,
                        "function": oldFileName, 
                        "type": "instructions", 
                        "hash": hashFunction.hexdigest(),
                        "instruction": instruction, 
                        "instructionCount": functionInstructions[instruction], 
                        "mean": mean,
                        "variance": variance
                    }
                )
    """

    def writeInstructionGroupFeatures(self, groups, allGroupSum, functionGroups, file):
        oldFileName = file
        bulkInsert = []
        for group in groups.keys():
            mean = (functionGroups[group][1] / float(allGroupSum))
            variance = ((functionGroups[group][1] - mean) ** 2 / allGroupSum)
            if functionGroups[group][1] > 0:
                hashFunction = md5()
                hashFunction.update((self.fileSHA256 + "," + file + "," + "groups," + group + "," + str(
                    functionGroups[group][1]) + "," + str(mean) + "," + str(variance)).encode('utf-8'))
                maxInstruction = max(functionGroups[group][0].items(), key=lambda x: x[1])
                maxInstructionCount = maxInstruction[1]
                maxInstruction = maxInstruction[0]

                for item in functionGroups[group][0].copy().keys():
                    if functionGroups[group][0][item] == 0:
                        del functionGroups[group][0][item]
                minInstruction = min(functionGroups[group][0].items(), key=lambda x: x[1])
                minInstructionCount = minInstruction[1]
                minInstruction = minInstruction[0]

                bulkInsert.append(
                    {"binaryFileName": self.fileName, "SHA256": self.fileSHA256, "Date Analyzed": self.dateAnalyzed,
                     "function": oldFileName, "type": "groups", "hash": hashFunction.hexdigest(), "group": group,
                     "groupCount": functionGroups[group][1], "mean": mean, "variance": variance,
                     "max_instruction": maxInstruction, "max_instruction_count": maxInstructionCount,
                     "min_instruction": minInstruction, "min_instruction_count": minInstructionCount})
        try:
            self.collection_functions.insert_many(bulkInsert)
        except Exception:
            pass

    """
    def run2(self):
        self.loadInstructionList()
        self.loadInstructionGroups()
        functionNamesToEA = {}

        ea = inf_get_min_ea()
        count = 0
        for funcea in Functions(get_segm_start(ea), get_segm_end(ea)):
            functionInstructions = deepcopy(self.instructions)
            functionGroups = deepcopy(self.groups)
            total = 0
            allGroupSum = 0
            functionName = get_func_name(funcea)
            functionNamesToEA[functionName] = funcea
            originalfuncea = funcea
            currentea = funcea
            while currentea != BADADDR and currentea < find_func_end(funcea):
                currentInstruction = print_insn_mnem(currentea)
                if currentInstruction in self.instructions.keys():
                    functionInstructions[currentInstruction] += 1
                    total += 1

                for group in self.groups.keys():
                    if currentInstruction in self.groups[group][0].keys():
                        functionGroups[group][1] += 1
                        functionGroups[group][0][currentInstruction] += 1
                        allGroupSum += 1

                currentea = next_head(currentea)
        return self.getInstructionFeatures(self.instructions,total,functionInstructions,functionName)
    """

    def run(self):
        self.loadInstructionList()
        self.loadInstructionGroups()
        functionNamesToEA = {}

        ea = inf_get_min_ea()
        for funcea in Functions(get_segm_start(ea), get_segm_end(ea)):
            functionInstructions = deepcopy(self.instructions)
            functionGroups = deepcopy(self.groups)
            total = 0
            allGroupSum = 0
            functionName = get_func_name(funcea)
            functionNamesToEA[functionName] = funcea
            currentea = funcea
            while currentea != BADADDR and currentea < find_func_end(funcea):
                currentInstruction = print_insn_mnem(currentea)
                if currentInstruction in self.instructions.keys():
                    functionInstructions[currentInstruction] += 1
                    total += 1

                for group in self.groups.keys():
                    if currentInstruction in self.groups[group][0].keys():
                        functionGroups[group][1] += 1
                        functionGroups[group][0][currentInstruction] += 1
                        allGroupSum += 1

                currentea = next_head(currentea)
            self.writeInstructionFeatures(self.instructions, total, functionInstructions, functionName)
            self.writeInstructionGroupFeatures(self.groups, allGroupSum, functionGroups, functionName)
        return functionNamesToEA

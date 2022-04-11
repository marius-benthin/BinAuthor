from hashlib import md5
from copy import deepcopy
from datetime import datetime
from operator import itemgetter
from pymongo import MongoClient

from ida_idaapi import BADADDR
from ida_nalt import get_root_filename
from idautils import GetInputFileMD5, Functions
from idc import next_head, print_insn_mnem, find_func_end, get_segm_start, get_segm_end
from ida_funcs import get_func_name
from ida_ida import inf_get_min_ea

from pluginConfigurations import getInstructionListPath, getGroupPath


class FeatureExtractor():
    def __init__(self):
        self.client = MongoClient('localhost', 27017)
        self.db = self.client.BinAuthor
        self.collection = self.db.Functions

        self.instructionList = pluginConfigurations.getInstructionListPath() + "InstructionList.txt"
        self.groupList = pluginConfigurations.getGroupPath() + "InstructionGroups.txt"

        self.instructions = {}
        self.groups = {}

        self.fileName = get_root_filename()
        self.fileMD5 = GetInputFileMD5()
        self.fileMD5
        self.dateAnalyzed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #load instructions into dictionary
    def loadInstructionList(self):
        for line in open(self.instructionList, "r"):
            self.instructions[line.replace(" ","").replace("\n","")] = 0

    def loadInstructionGroups(self):
        currentGroup = ''
        for line in open(self.groupList, "r"):
            if line.find("[") != -1:
               currentGroup = line.replace("[",'').replace("]",'').replace('\n','')
               self.groups[currentGroup] = [{},0]
            else:
               self.groups[currentGroup][0][line.replace('\n','')] = 0

    def writeInstructionFeatures(self,instructions,sum,functionInstructions,file):
        oldFileName = file
        bulkInsert = []
        for instruction in instructions.keys():
            mean = (functionInstructions[instruction]/float(sum))
            variance = ((functionInstructions[instruction] - mean)**2/sum)
            if functionInstructions[instruction] > 0:
                hashFunction = hashlib.md5()
                hashFunction.update(self.fileMD5 + "," + file + "," + "instructions," + instruction + "," + str(functionInstructions[instruction]) + "," + str(mean) + "," + str(variance))
                bulkInsert.append({"binaryFileName":self.fileName,"MD5":self.fileMD5,"Date Analyzed":self.dateAnalyzed,"function":oldFileName,"type":"instructions","hash":hashFunction.hexdigest(),"instruction": instruction,"instructionCount": functionInstructions[instruction], "mean": mean, "variance": variance})
        try:
            self.collection.insert_many(bulkInsert)
        except:
            pass

    # def getInstructionFeatures(self,instructions,sum,functionInstructions,file):
        # oldFileName = file
        # bulkInsert = []
        # for instruction in instructions.keys():
            # mean = (functionInstructions[instruction]/float(sum))
            # variance = ((functionInstructions[instruction] - mean)**2/sum)
            # if functionInstructions[instruction] > 0:
                # hashFunction = hashlib.md5()
                # hashFunction.update(self.fileMD5 + "," + file + "," + "instructions," + instruction + "," + str(functionInstructions[instruction]) + "," + str(mean) + "," + str(variance))
                # bulkInsert.append({"binaryFileName":self.fileName,"MD5":self.fileMD5,"Date Analyzed":self.dateAnalyzed,"function":oldFileName,"type":"instructions","hash":hashFunction.hexdigest(),"instruction": instruction,"instructionCount": functionInstructions[instruction], "mean": mean, "variance": variance})

            
    def writeInstructionGroupFeatures(self,groups,allGroupSum,functionGroups,file):
        oldFileName = file
        bulkInsert = []
        for group in groups.keys():
            mean = (functionGroups[group][1]/float(allGroupSum))
            variance = ((functionGroups[group][1] - mean)**2/allGroupSum)
            if functionGroups[group][1] > 0:
                hashFunction = hashlib.md5()
                hashFunction.update(self.fileMD5 + "," + file + "," + "groups," + group + "," + str(functionGroups[group][1]) + "," + str(mean) + "," + str(variance))
                maxInstruction = max(functionGroups[group][0].iteritems(), key=operator.itemgetter(1))                
                maxInstructionCount = maxInstruction[1]
                maxInstruction = maxInstruction[0]
                
                for item in functionGroups[group][0].keys():
                    if functionGroups[group][0][item] == 0:
                        del functionGroups[group][0][item]
                minInstruction = min(functionGroups[group][0].iteritems(), key=operator.itemgetter(1))
                minInstructionCount = minInstruction[1]
                minInstruction = minInstruction[0]
                
                bulkInsert.append({"binaryFileName":self.fileName,"MD5":self.fileMD5,"Date Analyzed":self.dateAnalyzed,"function":oldFileName,"type":"groups","hash":hashFunction.hexdigest(),"group":group,"groupCount":functionGroups[group][1],"mean":mean,"variance":variance,"max_instruction":maxInstruction,"max_instruction_count":maxInstructionCount,"min_instruction":minInstruction,"min_instruction_count":minInstructionCount})
        try:
            self.collection.insert_many(bulkInsert)
        except:
            pass

    # def run2(self):
        # self.loadInstructionList()
        # self.loadInstructionGroups()
        # functionNamesToEA = {}
            
        # ea = idc.BeginEA()
        # count = 0
        # for funcea in Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            # functionInstructions = copy.deepcopy(self.instructions)
            # functionGroups = copy.deepcopy(self.groups)
            # sum = 0
            # allGroupSum = 0
            # functionName = idc.GetFunctionName(funcea)
            # functionNamesToEA[functionName] = funcea
            # originalfuncea = funcea
            # currentea = funcea
            # while currentea != idc.BADADDR and currentea < idc.FindFuncEnd(funcea):
                # currentInstruction = idc.GetMnem(currentea)
                # if currentInstruction in self.instructions.keys():
                    # functionInstructions[currentInstruction] += 1
                    # sum += 1
                
                # for group in self.groups.keys():
                    # if currentInstruction in self.groups[group][0].keys():
                        # functionGroups[group][1] += 1
                        # functionGroups[group][0][currentInstruction] += 1
                        # allGroupSum += 1
                        
                # currentea = idc.NextHead(currentea)
            # return self.getInstructionFeatures(self.instructions,sum,functionInstructions,functionName)
         
    def run(self):
        self.loadInstructionList()
        self.loadInstructionGroups()
        functionNamesToEA = {}
            
        ea = idc.BeginEA()
        count = 0
        for funcea in Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            functionInstructions = copy.deepcopy(self.instructions)
            functionGroups = copy.deepcopy(self.groups)
            sum = 0
            allGroupSum = 0
            functionName = idc.GetFunctionName(funcea)
            functionNamesToEA[functionName] = funcea
            originalfuncea = funcea
            currentea = funcea
            while currentea != idc.BADADDR and currentea < idc.FindFuncEnd(funcea):
                currentInstruction = idc.GetMnem(currentea)
                if currentInstruction in self.instructions.keys():
                    functionInstructions[currentInstruction] += 1
                    sum += 1
                
                for group in self.groups.keys():
                    if currentInstruction in self.groups[group][0].keys():
                        functionGroups[group][1] += 1
                        functionGroups[group][0][currentInstruction] += 1
                        allGroupSum += 1
                        
                currentea = idc.NextHead(currentea)
            self.writeInstructionFeatures(self.instructions,sum,functionInstructions,functionName)
            self.writeInstructionGroupFeatures(self.groups,allGroupSum,functionGroups,functionName)
        return functionNamesToEA
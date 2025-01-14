from pymongo.collection import Collection

from ida_nalt import retrieve_input_file_sha256
from idc import get_func_attr, FUNCATTR_FLAGS
from ida_funcs import get_func, FUNC_LIB
from ida_kernwin import refresh_idaview_anyway, request_refresh, IWID_FUNCS

from Database.mongodb import MongoDB, Collections
from BinAuthorPlugin.Views import FunctionFilterView as FunctionFilterList
from BinAuthorPlugin.Algorithms import CategorizeFunction as FunctionCategorizer
from BinAuthorPlugin.Algorithms import FunctionFeatureExtractor as FeatureExtractor


class FunctionFilter:

    def __init__(self):
        self.functionNamesToEA = None
        self.collection_function_labels: Collection = MongoDB(Collections.function_labels).collection

    def init(self):
        pass

    def colorFunctions(self):

        fileSHA256: str = retrieve_input_file_sha256().hex()

        functionsToColor = list(self.collection_function_labels.find({"SHA256": fileSHA256}))

        userFunctions = [
            userfunc["function"] for userfunc in list(self.collection_function_labels.find(
                {"SHA256": fileSHA256, "type": "user"}
            ))
        ]
        compilerFunctions = [
            compilerfunc["function"] for compilerfunc in list(self.collection_function_labels.find(
                {"SHA256": fileSHA256, "type": "compiler"}
            ))
        ]
        otherFunctions = [
            otherfunc["function"] for otherfunc in list(self.collection_function_labels.find(
                {"SHA256": fileSHA256, "type": "other"}
            ))
        ]

        userFuncStat = (len(userFunctions) / float(len(functionsToColor))) * 100
        compilerFuncStat = (len(compilerFunctions) / float(len(functionsToColor))) * 100
        otherFuncStat = (len(otherFunctions) / float(len(functionsToColor))) * 100

        for function in functionsToColor:
            funcEA = self.functionNamesToEA[function["function"]]
            func = get_func(funcEA)
            flags = get_func_attr(funcEA, FUNCATTR_FLAGS)
            if ((flags & FUNC_LIB) != FUNC_LIB) and ((flags & 1152) != 1152):
                if function["type"] == "compiler":
                    # .update_one({'_id': p['_id']},{'$set': {'d.a': existing + 1}}, upsert=False)
                    func.color = 0xACC7FF
                if function["type"] == "other":
                    func.color = 0xCC6600
                if function["type"] == "user":
                    func.color = 0x80FFCC
        funcTypeStatsView = FunctionFilterList.FunctionFilterList()
        print(len(functionsToColor))
        print(self.collection_function_labels.count_documents({"SHA256": fileSHA256, "type": "user"}))
        funcTypeStatsView.setDetails([userFuncStat, compilerFuncStat, otherFuncStat],
                                     {"User": userFunctions, "Compiler": compilerFunctions, "Other": otherFunctions})
        funcTypeStatsView.Show()
        refresh_idaview_anyway()
        request_refresh(IWID_FUNCS)

    def run(self):
        extractor = FeatureExtractor.FeatureExtractor()
        categorizer = FunctionCategorizer.FunctionCategorizer()
        self.functionNamesToEA = extractor.run()
        categorizer.run()
        self.colorFunctions()

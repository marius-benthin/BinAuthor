from functools import reduce
from Levenshtein import distance
from pymongo.collection import Collection

from Database.mongodb import MongoDB, Collections
from BinAuthorPlugin.Algorithms.Choices import Choice1
from BinAuthorPlugin.Algorithms.Choices import Choice2
from BinAuthorPlugin.Algorithms.Choices import Choice18
from BinAuthorPlugin.Algorithms.Choices import Strings as StringsMatching
from BinAuthorPlugin.ExternalScripts.minhash import minhash


class AuthorClassification:

    def __init__(self):
        self.collection_functions: Collection = MongoDB(Collections.functions).collection
        self.collection_choice1: Collection = MongoDB(Collections.choice1).collection
        self.collection_choice2: Collection = MongoDB(Collections.choice2).collection
        self.collection_choice18: Collection = MongoDB(Collections.choice18).collection
        self.collection_strings: Collection = MongoDB(Collections.strings).collection
        self.choice1Results = {}
        self.choice2Results = {}
        self.choice18Results = {}
        self.stringResults = {}

    def getChoice1(self):
        choice1 = Choice1.Choice1()
        choice1 = choice1.getChoice1()
        features = choice1["features"]
        documents = self.collection_choice1.find_one(
            {
                "$or": [
                    {"features.0": features[0]},
                    {"features.1": features[1]},
                    {"features.2": features[2]},
                    {"features.3": features[3]},
                    {"features.4": features[4]},
                    {"features.5": features[5]},
                    {"features.6": features[6]},
                    {"features.7": features[7]},
                    {"features.8": features[8]},
                    {"features.9": features[9]},
                    {"features.10": features[10]}
                ]
            }
        )

        authorDic = {}
        for doc in documents:
            jaccardCoefficient = len(list(set(doc["features"]) & set(features))) / float(
                len(list(set(doc["features"]) | set(features))))
            if doc['Author Name'] not in authorDic.keys():
                authorDic[doc['Author Name']] = 1

            authorDic[doc['Author Name']] += 1

            if doc['Author Name'] not in self.choice1Results.keys():
                self.choice1Results[doc['Author Name']] = [jaccardCoefficient]
            else:
                self.choice1Results[doc['Author Name']].append(jaccardCoefficient)

        for author in authorDic.keys():
            self.choice1Results[author] = max(self.choice1Results[author])
        return self.choice1Results

    def getChoice2(self):

        choice2 = Choice2.Choice2()
        choice2 = choice2.getChoice2()
        library = choice2["LibraryFunctions"]
        returns = choice2["returns"]

        featureVector = list(library.values()) + list(returns.values()) + [
            choice2["calls"], choice2['printf without newline'], choice2['printf with newline']]

        documents = self.collection_choice2.find_one(
            {
                "$or": [
                    {'LibraryFunctions.cout': library['cout']},
                    {'LibraryFunctions.puts': library['puts']},
                    {'LibraryFunctions.clock': library['clock']},
                    {'LibraryFunctions.endl': library['endl']},
                    {'LibraryFunctions.exit': library['exit']},
                    {'LibraryFunctions.fprintf': library['fprintf']},
                    {'LibraryFunctions.printf': library['printf']},
                    {'LibraryFunctions.cerr': library['cerr']},
                    {'LibraryFunctions.fflush': library['fflush']},
                    {'LibraryFunctions.Xlength_error': library['Xlength_error']},
                    {"returns.retn": returns['retn']}, {"returns.ret": returns["ret"]},
                    {"calls": choice2["calls"]},
                    {'printf without newline': choice2['printf without newline']},
                    {'printf with newline': choice2['printf with newline']}
                ]
            }
        )

        authorDic = {}
        for doc in documents:
            docFeatureVector = list(doc["LibraryFunctions"].values()) + list(doc["returns"].values()) + [
                doc["calls"], doc['printf without newline'], doc['printf with newline']]
            jaccardCoefficient = len(list(set(docFeatureVector) & set(featureVector))) / float(
                len(list(set(docFeatureVector) | set(featureVector))))
            if doc['Author Name'] not in authorDic.keys():
                authorDic[doc['Author Name']] = 1

            authorDic[doc['Author Name']] += 1

            if doc['Author Name'] not in self.choice2Results.keys():
                self.choice2Results[doc['Author Name']] = [jaccardCoefficient]
            else:
                self.choice2Results[doc['Author Name']].append(jaccardCoefficient)

        for author in authorDic.keys():
            self.choice2Results[author] = max(self.choice2Results[author])
        return self.choice2Results

    def getChoice18(self):
        NUM_HASHES = 200
        HASHES_PER_BAND = 20
        # NUM_BANDS = 200 / HASHES_PER_BAND

        choice18 = Choice18.Choice18()
        choice18 = choice18.choice18A()
        allFunctionHashes = []
        # databaseQuery = {"$or":[]}
        candidateHashes = []
        candidateMatches = {}
        for function in choice18:
            allFunctionHashes += function

            if len(function) == 0:
                continue

            for funcMinhashes in function:
                minhashTemp = funcMinhashes["MinHashSignature"]
                register = funcMinhashes["register"]
                candidateHashes.append(minhashTemp)
                orQuery = {"$or": []}
                start = 0
                while start < (NUM_HASHES - 1):
                    andList = []
                    for counter in range(start, start + HASHES_PER_BAND):
                        andList.append({"MinHashSignature." + str(counter): minhashTemp[counter]})
                    orQuery["$or"].append({"$and": andList})
                    start += HASHES_PER_BAND

                documents = self.collection_choice18.find_one({"$and": [{"register": register}, orQuery]})

                for document in documents:
                    if document["Author Name"] not in candidateMatches.keys():
                        candidateMatches[document["Author Name"]] = []
                    candidateMatches[document["Author Name"]].append(
                        minhash.similarity(minhashTemp, document["MinHashSignature"]))

        # for candidate in candidateMatches.keys():
        #    self.choice18Results[candidate] = max(candidateMatches[candidate])
        authorDic = {}
        for candidate in candidateMatches.keys():
            NumberOfValues = float(len(candidateMatches[candidate]))
            total = 0
            for similarityScore in candidateMatches[candidate]:
                total += float(similarityScore)

            if candidate not in authorDic.keys():
                authorDic[candidate] = 1

            authorDic[candidate] += 1

            if candidate not in self.choice18Results.keys():
                self.choice18Results[candidate] = [total / NumberOfValues]
            else:
                self.choice18Results[candidate].append(total / NumberOfValues)

        for author in authorDic.keys():
            self.choice18Results[author] = max(self.choice18Results[author])
        return self.choice18Results

    def getStringSimilarityScores(self):
        strings = StringsMatching.CustomStrings()
        stringList = strings.getAllStringsA()

        Authors = {}

        documents = self.collection_strings.find_one()
        for document in documents:
            if document["Author Name"] not in Authors.keys():
                Authors[document["Author Name"]] = {"score": 0}
            allTargetSimilarities = []
            if len(document["Strings"]) == 0:
                continue
            for targetString in stringList:
                similarities = []
                for testString in document["Strings"]:
                    similarities.append(1 - (distance(str(targetString), str(testString)) / float(
                        max([len(targetString), len(testString)]))))

                # get the highest similarity value which should indicate the closest matched string
                allTargetSimilarities.append(max(similarities))
            # compute the average score for the similarity between target and test application
            Authors[document["Author Name"]]["score"] = (
                    reduce(lambda x, y: x + y, allTargetSimilarities) / len(allTargetSimilarities)
            )
        return Authors

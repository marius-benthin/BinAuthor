from sys import argv
from os import listdir, path
from shlex import split
from subprocess import call
from multiprocessing import Pool
from pymongo.collection import Collection

from config import Config
from Database.mongodb import MongoDB, Collections

config: Config = Config()


def executeScripts(file):
    scriptsFolder = path.dirname(path.realpath(__file__)) + ""
    choice1 = path.join(scriptsFolder, "computeChoices.py")
    fileToAnalyze = file[0]
    AuthorName = file[1]

    executionString = split(
        'cmd.exe /c idaw.exe -A -S"' + choice1 + ' \\"' + AuthorName + '\\"" ' + '"' + fileToAnalyze + '"')
    call(executionString)


def main():
    mypath = argv[1]
    multiple = 0

    author = None
    if len(argv) >= 3:
        if "1" in argv[2]:
            author = mypath.split("/")[-1:][0]
            multiple = 1
        else:
            author = argv[3]

    collection_test: Collection = MongoDB(Collections.test).collection
    collection_test.insert_one({"mypath": mypath, "multiple": multiple, "author": author})

    onlyfiles = [[path.join(mypath, f), author] for f in listdir(mypath) if path.isfile(path.join(mypath, f))]
    onlyfolders = [path.join(mypath, f) for f in listdir(mypath) if path.isdir(path.join(mypath, f))]

    if multiple == 1:
        for folder in onlyfolders:
            folderName = path.basename(folder)
            onlyfiles = onlyfiles + [[path.join(folder, f), folderName] for f in listdir(folder) if
                                     path.isfile(path.join(folder, f))]

    processPool = Pool(10)
    processPool.map(executeScripts, onlyfiles)


if __name__ == "__main__":
    main()

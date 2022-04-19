from enum import Enum
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection

from config import Config


class Collections(str, Enum):
    strings = "Strings"
    choice1 = "Choice1"
    choice2 = "Choice2"
    choice18 = "Choice18"
    mahalanobis = "Mahalanobis"
    functions = "Functions"
    group_labels = "GroupLabels"
    function_labels = "FunctionLabels"
    function_fingerprint = "FunctionFingerPrint"
    test = "test"


class MongoDB:

    def __init__(self, collection: Collections):
        _config: Config = Config()
        self._client: MongoClient = MongoClient(_config.mongodb_uri)
        self._database: Database = self._get_database(_config.mongodb_database)
        self.collection: Collection = self._get_collection(collection.value)

    def _get_database(self, name: str) -> Database:
        """
        Get the database and create it if it not exists
        :param name: database name
        :return: database
        """
        if name not in self._client.list_database_names():
            return self._client[name]
        else:
            return self._client.get_database(name)

    def _get_collection(self, name: str) -> Collection:
        """
        Get the collection and create it if it not exists
        :param name: collection name
        :return: collection
        """
        if name not in self._database.list_collection_names():
            return self._database[name]
        else:
            return self._database.get_collection(name)

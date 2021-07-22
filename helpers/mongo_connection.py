import pymongo
import os

client = pymongo.MongoClient(os.getenv('MONGO_CONN'))
db = client[os.getenv('MONGO_DB')]

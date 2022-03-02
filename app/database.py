# import pymongo
from pymongo import MongoClient

client = MongoClient()
# client.drop_database('virustotal')
virustotal_db = client.virustotal
cuckoo_db = client.cuckoo
# db.create_index([('md5', pymongo.ASCENDING)],  unique=True)

if __name__ == "__main__":
    # collection = db.test_collection
    #
    # post = {"author": "Mike",
    #         "text": "My first blog post!",
    #         "tags": ["mongodb", "python", "pymongo"]}
    # collection.insert_one(post)

    # from pprint import pprint
    # cuckoo_coll = cuckoo_db.analysis
    # query = {"target.file.md5": "ac2bdbc6ceaac78735cdff654e1fbc78"}
    # doc = cuckoo_coll.find_one(query)
    #
    # pprint(doc)

    pass

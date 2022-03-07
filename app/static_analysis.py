import database
import capa
import manalyze
import pymongo
import file_info

sample_coll = database.static_analysis_db.test
sample_coll.create_index([("md5", pymongo.ASCENDING)],  unique=True)
if __name__ == "__main__":
    sample_path = "/home/andy/Desktop/Setup.exe"
    capa_dict = capa.capa(sample_path)
    manalyze_dict = manalyze.manalyze(sample_path)
    file_info_object = file_info.FileInfo(sample_path)
    file_info_dict = file_info_object.all_file_info_not_none()

    # post = {"md5": file_info_dict["md5"], "file_info": file_info_dict, "capa": capa_dict}
    post = {"md5": file_info_dict["md5"], "file_info": file_info_dict, "capa": capa_dict, "manalyze": manalyze_dict}
    sample_coll.insert_one(post)


    # post = {"author": "Mike",
    #         "md5": "ac2bdbc6ceaac78735cdff654e1fbc78",
    #         "hex_md5": hex_md5("ac2bdbc6ceaac78735cdff654e1fbc78"),
    #         "tags": ["mongodb", "python", "pymongo"]}
    # sample_coll.insert_one(post)

    # from pprint import pprint
    #
    # query = {"target.file.md5": "ac2bdbc6ceaac78735cdff654e1fbc78"}
    # doc = sample_coll.find_one(query)
    #
    # pprint(doc)

import database
import static.capa as capa
import static.manalyze as manalyze
import pymongo
import static.file_info as file_info
import static.flare_strings as flare_strings
import static.peframe as peframe

sample_coll = database.static_analysis_db.test
sample_coll.create_index([("md5", pymongo.ASCENDING)], unique=True)

if __name__ == "__main__":
    sample_path = "/home/andy/Desktop/WcInstaller(1).exe"
    file_info_object = file_info.FileInfo(sample_path)
    file_info_dict = file_info_object.all_file_info_not_none()

    # string_ranks = flare_strings.flare(sample_path)
    # capa_dict = capa.capa(sample_path)
    # manalyze_dict = manalyze.manalyze(sample_path)
    
    peframe_dict = peframe.peframe(sample_path)

    # doc = {
    #     "md5": file_info_dict["md5"],
    #     "file_info": file_info_dict,
    #     "capa": capa_dict,
    #     "manalyze": manalyze_dict,
    #     "string_rank": string_ranks
    # }

    doc = {
        "md5": file_info_dict["md5"],
        "file_info": file_info_dict,
        "peframe": peframe_dict
        }

    sample_coll.insert_one(doc)

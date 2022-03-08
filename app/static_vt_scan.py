import os
import virus_total
import utils
# from static.file_info import FileInfo
import static.capa as capa
import static.manalyze as manalyze
import static.file_info as file_info
import static.flare_strings as flare_strings
import static.peframe as peframe
from pprint import pprint
from time import sleep
import database
import sys

def add_samples_to_database(samples_dir):
    file_list = []
    md5_list = []
    for root, dirs, files in os.walk(samples_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_info_object = file_info.FileInfo(file_path)
            # file_info_dict = file_info_object.all_file_info_not_none()
            mime_type = file_info_object.mime_type()  # file_info_dict["mime_type"]
            file_md5 = file_info_object.md5()
            if mime_type.startswith("application") and file_md5 not in md5_list:
                md5_list.append(file_md5)
                file_list.append(file_path)
            else:
                pass

    total_files = len(file_list)
    count = 0
    for file_path in file_list:
        count += 1
        print(f"{utils.now()} - {count} of {total_files} - {file_path}")

        file_info_object = file_info.FileInfo(file_path)
        file_info_dict = file_info_object.all_file_info_not_none()
        # flare_strings_output_dict = flare_strings.flare(file_path)
        # capa_dict = capa.capa(file_path)
        # manalyze_dict = manalyze.manalyze(file_path)
        # peframe_dict = peframe.peframe(file_path)
        #
        # doc = {
        #     "md5": file_info_dict["md5"],
        #     "file_info": file_info_dict,
        #     "capa": capa_dict,
        #     "manalyze": manalyze_dict,
        #     "peframe": peframe_dict,
        #     "string_rank": flare_strings_output_dict,
        #     "vt": {
        #         "uploaded_to_vt": False,
        #         "vt_analysis_complete" : False,
        #         "vt_analysis_retrieved" : False
        #         }
        # }

        doc = {
            "md5": file_info_dict["md5"],
            "file_info": file_info_dict,
            "vt": {
                "uploaded_to_vt": False,
                "vt_analysis_complete" : False,
                "vt_analysis_retrieved" : False
                }
        }
        static_and_vt_analysis_coll.insert_one(doc)

    return


def upload_files():
    uploaded_query = {"vt.uploaded_to_vt": False}
    total = static_and_vt_analysis_coll.count_documents(uploaded_query)
    count = 0

    for doc in static_and_vt_analysis_coll.find(uploaded_query)[0:total]:
        count += 1
        print(f"{utils.now()} - {count} of {total}")
        analysis_id = virus_total.upload_file(doc["file_info"]["file_path"])
        static_and_vt_analysis_coll.update_one(
            {"_id": doc["_id"]},
            {"$set": {"vt.uploaded_to_vt": True, "vt.analysis_id": analysis_id}},
            upsert=False
        )
        print(f"{utils.now()} - Analysis id: {analysis_id}")
        if count < total:
            print(f"{utils.now()} - Sleeping {virus_total_sleep_time} seconds")
            sleep(virus_total_sleep_time)
        else:
            print(f"{utils.now()} - Uploads complete")


def static_analysis():
    total = static_and_vt_analysis_coll.count_documents({})
    total_remaining = total
    count = 0

    for doc in static_and_vt_analysis_coll.find():
        count += 1

        file_path = doc["file_info"]["file_path"]
        print(f"{utils.now()} - {count} of {total} - {file_path}")

        flare_strings_output_dict = flare_strings.flare(file_path)
        capa_dict = capa.capa(file_path)
        manalyze_dict = manalyze.manalyze(file_path)
        peframe_dict = peframe.peframe(file_path)

        static_and_vt_analysis_coll.update_one(
            {"_id": doc["_id"]},
            {"$set": {"capa": capa_dict,
                      "manalyze": manalyze_dict,
                      "peframe": peframe_dict,
                      "string_rank": flare_strings_output_dict}
                      },
            upsert=False)


def retrieve_analysis_status():
    retrieve_query = {"vt.uploaded_to_vt": True, "vt.vt_analysis_complete": False}
    total = static_and_vt_analysis_coll.count_documents(retrieve_query)
    total_remaining = total
    count = 0

    while total_remaining > 0:
        for doc in static_and_vt_analysis_coll.find(retrieve_query):
            count += 1
            print(f"{utils.now()} - {count} of {total}")
            # pprint(doc, indent=4)
            analysis_complete_status = virus_total.analysis_status(
                doc["vt"]["analysis_id"])
            if analysis_complete_status is True:
                print(f"{utils.now()} - Analysis status: complete")
                static_and_vt_analysis_coll.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"vt.vt_analysis_complete": True,
                              "vt.vt_analysis_retrieved": False}},
                    upsert=False)
                total_remaining -= 1
            else:
                print(f"{utils.now()} - Analysis status: in progress")
            if count < total:
                print(f"{utils.now()} - Sleeping {virus_total_sleep_time} seconds ")
                sleep(virus_total_sleep_time)

        if total_remaining > 0:
            count = 0
            seconds = 60
            minutes = 10
            analysis_wait_sleep_time = seconds * minutes
            print(f"{utils.now()} - {total_remaining} file analyses still in progess. Sleeping {minutes} minutes")
            sleep(analysis_wait_sleep_time)


def retrieve_analysis_results():
    retrieve_query = {"vt.vt_analysis_complete": True,
                      "vt.vt_analysis_retrieved": False}
    total = static_and_vt_analysis_coll.count_documents(retrieve_query)
    count = 0

    for doc in static_and_vt_analysis_coll.find(retrieve_query)[0:total]:
        count += 1
        print(f"{utils.now()} - {count} of {total}")
        pprint(doc, indent=4)

        # last_analysis_result = virus_total.last_analysis_results(doc["md5"])
        # pprint(last_analysis_result)
        # static_and_vt_analysis_coll.update_one({"_id":doc["_id"]}, {"$set": {"vt_analysis_retrieved": True, "last_analysis_result": last_analysis_result }}, upsert=False)

        all_scan_results_dict = virus_total.all_scan_results(doc["md5"])
        pprint(all_scan_results_dict)
        for k, v in all_scan_results_dict.items():
            static_and_vt_analysis_coll.update_one(
                {"_id": doc["_id"]},
                {"$set": {"vt.vt_analysis_retrieved": True, k: v}},
                upsert=False
            )

        if count < total:
            print(f"{utils.now()} - Sleeping {virus_total_sleep_time} seconds")
            sleep(virus_total_sleep_time)


virus_total_sleep_time = 20
static_and_vt_analysis_coll = database.static_and_vt_analysis_coll

if __name__ == "__main__":
    file_dir = os.path.dirname(os.path.abspath(__file__))
    file_dir_split = os.path.split(file_dir)
    sample_dir = os.path.join(file_dir_split[0], "sample")

    # add_samples_to_database(samples_dir=sample_dir)
    # upload_files()
    # static_analysis()
    retrieve_analysis_status()
    retrieve_analysis_results()

    pass

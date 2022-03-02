import os
import virus_total
import utils
import file_info
from pprint import pprint
from time import sleep
import database


def add_samples_to_database(samples_dir):
    file_dict_list = []
    md5_list = []
    for root, dirs, files in os.walk(samples_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if os.path.isfile:
                file_info_object = file_info.FileInfo(file_path)
                file_info_dict = file_info_object.all_file_info_not_none()
                file_md5 = file_info_dict["md5"]
                mime_type = file_info_dict["mime_type"]
                if mime_type.startswith("application"):
                    if file_md5 not in md5_list:
                        file_info_dict["file_path"] = file_path
                        file_info_dict["uploaded"] = False
                        file_info_dict["vt_analysis_complete"] = False
                        file_info_dict["vt_analysis_retrieved"] = False

                        md5_list.append(file_md5)
                        file_dict_list.append(file_info_dict)
                        collection.insert_one(file_info_dict)

    return file_dict_list


def upload_files():
    uploaded_query = {"uploaded": False}
    total = collection.count_documents(uploaded_query)
    count = 0

    for doc in collection.find(uploaded_query)[0:total]:
        count += 1
        print(f"{utils.now()} - {count} of {total}")
        analysis_id = virus_total.upload_file(doc["file_path"])
        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"uploaded": True, "analysis_id": analysis_id}},
            upsert=False
        )
        print(f"{utils.now()} - Analysis id: {analysis_id}")
        if count < total:
            print(f"{utils.now()} - Sleeping {virus_total_sleep_time} seconds")
            sleep(virus_total_sleep_time)
        else:
            print(f"{utils.now()} - Uploads complete")


def retrieve_analysis_status():
    retrieve_query = {"uploaded": True, "vt_analysis_complete": False}
    total = collection.count_documents(retrieve_query)
    total_remaining = total
    count = 0

    while total_remaining > 0:
        for doc in collection.find(retrieve_query):
            count += 1
            print(f"{utils.now()} - {count} of {total}")
            # pprint(doc, indent=4)
            analysis_complete_status = virus_total.analysis_status(
                doc["analysis_id"])
            if analysis_complete_status is True:
                print(f"{utils.now()} - Analysis status: complete")
                collection.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"vt_analysis_complete": True,
                              "vt_analysis_retrieved": False}},
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
    retrieve_query = {"vt_analysis_complete": True,
                      "vt_analysis_retrieved": False}
    total = collection.count_documents(retrieve_query)
    count = 0

    for doc in collection.find(retrieve_query)[0:total]:
        count += 1
        print(f"{utils.now()} - {count} of {total}")
        pprint(doc, indent=4)

        # last_analysis_result = virus_total.last_analysis_results(doc["md5"])
        # pprint(last_analysis_result)
        # collection.update_one({"_id":doc["_id"]}, {"$set": {"vt_analysis_retrieved": True, "last_analysis_result": last_analysis_result }}, upsert=False)

        all_scan_results_dict = virus_total.all_scan_results(doc["md5"])
        pprint(all_scan_results_dict)
        for k, v in all_scan_results_dict.items():
            collection.update_one(
                {"_id": doc["_id"]},
                {"$set": {"vt_analysis_retrieved": True, k: v}},
                upsert=False
            )

        if count < total:
            print(f"{utils.now()} - Sleeping {virus_total_sleep_time} seconds")
            sleep(virus_total_sleep_time)


virus_total_sleep_time = 20
collection = database.virustotal_db.setup_exe_3

if __name__ == "__main__":
    # file_dir = os.path.dirname(os.path.abspath(__file__))
    # file_dir_split = os.path.split(file_dir)
    # sample_dir = os.path.join(file_dir_split[0], "sample")
    # add_samples_to_database(samples_dir=sample_dir)
    # upload_files()

    # retrieve_analysis_status()
    # retrieve_analysis_results()

    pass

import database
# from pprint import pprint
import utils
# import sys
import os


def cuckoo_signatures(vt_doc):
    vt_md5 = vt_doc["md5"]
    severity_dict = {"1": "low", "2": "medium", "3": "high"}
    query = {"target.file.md5": vt_md5}
    doc = cuckoo_coll.find_one(query)

    new_doc_list = []
    for signature in doc["signatures"]:
        for mark in signature["marks"]:

            try:
                mark["call"].pop('time', None)
            except KeyError:
                pass

            try:
                mark["call"].pop('status', None)
            except KeyError:
                pass

            try:
                mark["call"].pop('tid', None)
            except KeyError:
                pass

            try:
                mark["call"].pop('stacktrace', None)
            except KeyError:
                pass

            try:
                mark.pop('pid', None)
            except KeyError:
                pass

            try:
                mark.pop('cid', None)
            except KeyError:
                pass

        new_doc = {}

        new_doc["description"] = signature["description"]
        new_doc["name"] = signature["name"]
        new_doc["severity"] = severity_dict[str(signature["severity"])]
        new_doc["event_count"] = signature["markcount"]
        new_doc["events"] = signature["marks"]

        new_doc_list.append(new_doc)

    new_doc_list.reverse()
    vt_doc["behaviour"] = new_doc_list
    vt_doc.pop('_id', None)
    vt_doc.pop('analysis_id', None)
    vt_doc.pop('sigma_analysis_stats', None)
    vt_doc.pop('sigma_analysis_summary', None)
    vt_doc.pop('total_votes', None)
    vt_doc.pop('unique_sources', None)
    vt_doc.pop('file_path', None)
    vt_doc.pop('uploaded', None)
    vt_doc.pop('vt_analysis_complete', None)
    vt_doc.pop('vt_analysis_retrieved', None)

    report_file = os.path.join(report_dir, f"cuckoo_analysis.{vt_md5}.json")
    utils.create_json_file(report_file, vt_doc)


virustotal_coll = database.virustotal_db.setup_exe_3
cuckoo_coll = database.cuckoo_db.analysis

file_dir = os.path.dirname(os.path.abspath(__file__))
file_dir_split = os.path.split(file_dir)
report_dir = os.path.join(file_dir_split[0], "reports")

if __name__ == "__main__":
    for vt_doc in virustotal_coll.find()[0:1]:
        cuckoo_signatures(vt_doc)

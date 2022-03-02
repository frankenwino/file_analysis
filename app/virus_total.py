import vt
from pprint import pprint
# import time
import os
import utils
from file_info import FileInfo
import sys


def check_file(file_md5):
    scan_result = client.get_object(f"/files/{file_md5}")

    return scan_result


def upload_file(file_path):
    print(f"{utils.now()} - Uploading {file_path}")
    with open(file_path, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=False)
    print(f"{utils.now()} - Upload completed")

    return analysis.id


def analysis_status(analysis_id):
    print(f"{utils.now()} - Checking analysis status of {analysis_id}")
    analysis = client.get_object(f"/analyses/{analysis_id}")
    if analysis.status == "completed":
        print(f"{utils.now()} - Analysis complete {analysis_id}")
        return True
    else:
        return False


def last_analysis_results(file_md5):
    scan_result = client.get_object(f"/files/{file_md5}")
    last_analysis_results = scan_result.last_analysis_results

    return last_analysis_results


def detected_only_dict(detection_dict):
    detected_only_dict = {}

    for vendor, vendor_result_dict in sorted(detection_dict.items()):
        if vendor_result_dict["category"] != "undetected":
            detected_only_dict[vendor] = vendor_result_dict

    return detected_only_dict


def all_scan_results(file_md5):
    """
    Options for scan result

    authentihash, context_attributes, creation_date, crowdsourced_yara_results,
    first_submission_date, from_dict, get, id, last_analysis_date,
    last_analysis_results, last_analysis_stats, last_modification_date,
    last_submission_date, magic, md5, meaningful_name, names, packers, pe_info,
    popular_threat_classification, relationships, reputation, sandbox_verdicts,
    set_data, sha1, sha256, sigma_analysis_stats, sigma_analysis_summary,
    signature_info, size, ssdeep, tags, times_submitted, tlsh, to_dict,
    total_votes, trid, type, type_description, type_extension, type_tag,
    unique_sources, vhash
    """

    scan_result = client.get_object(f"/files/{file_md5}")

    result_dict = {}

    try:
        result_dict["crowdsourced_yara_results"] = scan_result.crowdsourced_yara_results
    except AttributeError:
        pass

    try:
        last_analysis_results_dict = scan_result.last_analysis_results
        detection_only_last_analysis_results_dict = detected_only_dict(last_analysis_results_dict)
        result_dict["last_analysis_results"] = detection_only_last_analysis_results_dict
    except AttributeError:
        pass

    try:
        result_dict["last_analysis_stats"] = scan_result.last_analysis_stats
    except AttributeError:
        pass

    try:
        result_dict["packers"] = scan_result.packers
    except AttributeError:
        pass

    try:
        result_dict["pe_info"] = scan_result.pe_info
    except AttributeError:
        pass

    try:
        result_dict["popular_threat_classification"] = scan_result.popular_threat_classification
    except AttributeError:
        pass

    try:
        result_dict["relationships"] = scan_result.relationships
    except AttributeError:
        pass

    try:
        result_dict["reputation"] = scan_result.reputation
    except AttributeError:
        pass

    try:
        result_dict["sandbox_verdicts"] = scan_result.sandbox_verdicts
    except AttributeError:
        pass

    try:
        result_dict["sigma_analysis_stats"] = scan_result.sigma_analysis_stats
    except AttributeError:
        pass

    try:
        result_dict["sigma_analysis_summary"] = scan_result.sigma_analysis_summary
    except AttributeError:
        pass

    try:
        result_dict["signature_info"] = scan_result.signature_info
    except AttributeError:
        pass

    try:
        result_dict["ssdeep"] = scan_result.ssdeep
    except AttributeError:
        pass

    try:
        result_dict["tags"] = scan_result.tags
    except AttributeError:
        pass

    try:
        result_dict["total_votes"] = scan_result.total_votes
    except AttributeError:
        pass

    try:
        result_dict["trid"] = scan_result.trid
    except AttributeError:
        pass

    try:
        result_dict["unique_sources"] = scan_result.unique_sources
    except AttributeError:
        pass

    return result_dict


def get_apy_key():
    config_file = os.path.join(file_dir, "config", "config.ini")
    config_data = utils.get_config(config_file)
    api_key = config_data["virus_total"]["api"]

    return api_key


file_dir = os.path.dirname(os.path.abspath(__file__))
api_key = get_apy_key()
client = vt.Client(api_key)

if __name__ == "__main__":
    file_dir_split = os.path.split(file_dir)
    sample_dir = os.path.join(file_dir_split[0], "sample")
    file_path = os.path.join(sample_dir, "Setup.exe")
    file_info_object = FileInfo(file_path)
    file_md5 = file_info_object.md5()

    scan_results_dict = all_scan_results(file_md5)
    pprint(scan_results_dict)
    utils.create_json_file("last_analysis_results.json", scan_results_dict)

    sys.exit(0)

    """
    # analysis_id = upload_file(file_path)
    # print(f"{utils.now()} - Analysis id: {analysis_id}")
    """

    scan_result = check_file(file_md5)
    print(dir(scan_result))
    # pprint(scan_result.last_analysis_results, indent=4)

    """
    # scanned_file = client.get_object(f"/files/{file_md5}")
    # last_analysis_results = scanned_file.last_analysis_results
    # print(type(last_analysis_results))
    """

    """
    # json_file_path = f"{file_path}.last_analysis_results.json"
    # print(json_file_path)
    # utils.create_json_file(json_file_path, last_analysis_results)
    """

    # analysis_status(analysis_id="MDQ3ZDc0NmM4N2FjZWExMGY2NWZiNjY3ZDRhYTMyY2Q6MTY0NjAzODEwNw==")

"""
https://github.com/VirusTotal/vt-py
https://virustotal.github.io/vt-py/
"""

import vt
from pprint import pprint
# import time
import os
import utils
from static.file_info import FileInfo
import sys
import database

def check_file(file_md5):
    scan_result = client.get_object(f"/files/{file_md5}")

    return scan_result


def upload_file(file_path):
    print(f"{utils.now()} - Uploading {file_path}")
    with open(file_path, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=False)
    print(f"{utils.now()} - Upload completed")

    return analysis.id


def scan_url(url):
    analysis = client.scan_url(url)

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


def file_detected_only_dict(detection_dict):
    file_detected_only_dict = {}

    for vendor, vendor_result_dict in sorted(detection_dict.items()):
        if vendor_result_dict["category"] != "undetected":
            file_detected_only_dict[vendor] = vendor_result_dict

    return file_detected_only_dict


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
        detection_only_last_analysis_results_dict = file_detected_only_dict(
            last_analysis_results_dict)
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


def url_detected_only_dict(detection_dict):

    """
    file_detected_only_dict = {}

    for vendor, vendor_result_dict in sorted(detection_dict.items()):
        if vendor_result_dict["category"] != "undetected":
            file_detected_only_dict[vendor] = vendor_result_dict

    return file_detected_only_dict
    """

    url_detected_only_dict = {}

    ignore_list = ["harmless", "undetected"]

    for vendor, vendor_result_dict in sorted(detection_dict.items()):
        if vendor_result_dict["category"] not in ignore_list:
            url_detected_only_dict[vendor] = vendor_result_dict

    return url_detected_only_dict


def url_scan_results(url):
    """
    Options for scan result

    categories, context_attributes, first_submission_date, from_dict,
    get, html_meta, id, last_analysis_date, last_analysis_results,
    last_analysis_stats, last_final_url, last_http_response_code,
    last_http_response_content_length, last_http_response_content_sha256,
    last_http_response_headers, last_modification_date,
    last_submission_date, outgoing_links, relationships, reputation,
    set_data, tags, threat_names, times_submitted, title, to_dict,
    total_votes, trackers, type, url
    """
    url_id = vt.url_id(url)
    # print(url_id)
    url_result = client.get_object("/urls/{}", url_id)
    # print(dir(url_result))

    # url_dict = {
    #     "categories": url_result.categories,
    #     "context_attributes": url_result.context_attributes,
    #     "from_dict": url_result.from_dict,
    #     "get": url_result.get,
    #     "html_meta": url_result.html_meta,
    #     "id": url_result.id,
    #     "last_analysis_date": url_result.last_analysis_date,
    #     "last_analysis_results": url_result.last_analysis_results,
    #     "last_analysis_stats": url_result.last_analysis_stats,
    #     "last_final_url": url_result.last_final_url,
    #     "last_http_response_code": url_result.last_http_response_code,
    #     "last_http_response_content_length": url_result.last_http_response_content_length,
    #     "last_http_response_content_sha256": url_result.last_http_response_content_sha256,
    #     "last_http_response_headers": url_result.last_http_response_headers,
    #     "last_modification_date": url_result.last_modification_date,
    #     "last_submission_date": url_result.last_submission_date,
    #     "outgoing_links": url_result.outgoing_links,
    #     "relationships": url_result.relationships,
    #     "reputation": url_result.reputation,
    #     "set_data": url_result.set_data,
    #     "tags": url_result.tags,
    #     "threat_names": url_result.threat_names,
    #     "times_submitted": url_result.times_submitted,
    #     "title": url_result.title,
    #     "to_dict": url_result.to_dict,
    #     "total_votes": url_result.total_votes,
    #     "trackers": url_result.trackers,
    #     "type": url_result.type,
    #     "url": url_result.url
    # }

    url_dict = {}
    try:
        url_dict["categories"] = url_result.categories
    except AttributeError:
        pass

    try:
        url_dict["context_attributes"] = url_result.context_attributes
    except AttributeError:
        pass

    try:
        url_dict["html_meta"] = url_result.html_meta
    except AttributeError:
        pass

    try:
        url_dict["id"] = url_result.id
    except AttributeError:
        pass

    try:
        url_dict["last_analysis_date"] = utils.datetime_to_string(url_result.last_analysis_date)
    except AttributeError:
        pass

    try:
        url_dict["last_analysis_results"] = url_detected_only_dict(url_result.last_analysis_results)
    except AttributeError:
        pass

    try:
        url_dict["last_analysis_stats"] = url_result.last_analysis_stats
    except AttributeError:
        pass

    try:
        url_dict["last_final_url"] = url_result.last_final_url
    except AttributeError:
        pass


    try:
        url_dict["last_http_response_code"] = url_result.last_http_response_code
    except AttributeError:
        pass

    try:
        url_dict["last_http_response_content_length"] = url_result.last_http_response_content_length
    except AttributeError:
        pass

    try:
        url_dict["last_http_response_content_sha256"] = url_result.last_http_response_content_sha256
    except AttributeError:
        pass

    try:
        url_dict["last_http_response_headers"] = url_result.last_http_response_headers
    except AttributeError:
        pass


    try:
        url_dict["last_modification_date"] = utils.datetime_to_string(url_result.last_modification_date)
    except AttributeError:
        pass


    try:
        url_dict["last_submission_date"] = utils.datetime_to_string(url_result.last_submission_date)
    except AttributeError:
        pass


    try:
        url_dict["outgoing_links"] = url_result.outgoing_links
    except AttributeError:
        pass


    try:
        url_dict["relationships"] = url_result.relationships
    except AttributeError:
        pass

    try:
        url_dict["reputation"] = url_result.reputation
    except AttributeError:
        pass
    try:
        url_dict["tags"] = url_result.tags
    except AttributeError:
        pass

    try:
        url_dict["threat_names"] = url_result.threat_names
    except AttributeError:
        pass

    try:
        url_dict["times_submitted"] = url_result.times_submitted
    except AttributeError:
        pass

    try:
        url_dict["title"] = url_result.title
    except AttributeError:
        pass

    try:
        url_dict["total_votes"] = url_result.total_votes
    except AttributeError:
        pass

    try:
        url_dict["trackers"] = url_result.trackers
    except AttributeError:
        pass

    try:
        url_dict["type"] = url_result.type
    except AttributeError:
        pass

    try:
        url_dict["url"] = url_result.url
    except AttributeError:
        pass


    return url_dict


file_dir = os.path.dirname(os.path.abspath(__file__))
api_key = get_apy_key()
client = vt.Client(api_key)

if __name__ == "__main__":

    url = "http://cacerts.digicert.com/DigiCertSHA2AssuredIDTimestampingCA.crt0"
    url_analysis_id = "u-b6569cb2af5a8f426bfb55095159375122cdb353b4e5b9f14c324f0960555935-1646769721" # scan_url(url)
    # print(url_analysis_id)

    # analysis_status(url_analysis_id)

    url_scan_results_dict = url_scan_results(url)

    pprint(url_scan_results_dict, indent=4)

    json_file_path = "url_results.json"
    print(json_file_path)
    utils.create_json_file(json_file_path, url_scan_results_dict)

    sys.exit(0)
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

import subprocess
from pprint import pprint
import json
import utils
import os


def capa(sample_file_path):
    """
    https://github.com/mandiant/capa/blob/master/doc/installation.md
    https://github.com/mandiant/capa-rules
    """
    print(f"{utils.now()} - capa scan in progress...")
    capa_rules_dir = os.path.join(file_dir, "capa-rules")
    capa_sigs_dir = os.path.join(file_dir, "capa-sigs")

    # subprocess.call([
    #     "capa",
    #     "-jq",
    #     "-r", capa_rules_dir,
    #     "-s", capa_sigs_dir,
    #     sample_file_path
    #     ])

    output = subprocess.check_output([
        "capa",
        "-jq",
        "-r", capa_rules_dir,
        "-s", capa_sigs_dir,
        sample_file_path
    ])
    output_dict = json.loads(output.decode("utf-8"))

    pprint(output_dict, indent=4)

    report_file_path = os.path.join(report_dir, "capa.json")
    utils.create_json_file(report_file_path, output_dict)

    print(f"{utils.now()} - capa scan complete")

    return output_dict


file_dir = os.path.dirname(os.path.abspath(__file__))
file_dir_split = os.path.split(file_dir)
report_dir = os.path.join(file_dir_split[0], "reports")
if not os.path.isdir(report_dir):
    os.makedirs(report_dir)

if __name__ == "__main__":
    sample_file_path = os.path.join(file_dir_split[0], "sample", "Setup.exe")
    capa(sample_file_path)

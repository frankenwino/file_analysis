from . import utils_cheat
import subprocess
from pprint import pprint
import json
import os
import converter

"""
https://docs.manalyzer.org/en/latest/index.html
https://github.com/JusticeRage/Manalyze

Install manalyze

$ sudo apt install libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git
$ git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze
$ cmake .
$ make install -j5
$ manalyze --version
# $ cd bin && ./manalyze --version
"""


def manalyze(file_path):
    print(f"{utils_cheat.now()} - manalyze scan in progress...")
    # print("manalyze scan in progress...")
    # this_file = utils_cheat.get_file_method(__file__, sys._getframe(  ).f_code.co_name)
    # print(f"{utils_cheat.now()} - {file_path}")

    # subprocess.call(["manalyze", "-dall", file_path, "-o", "json"])
    # output = subprocess.check_output(["manalyze", "-dall", file_path, "-o", "json"])
    output = subprocess.check_output(["manalyze", "-d", "all", "-p", "all", "--pe", file_path, "-o", "json"])
    output_dict = json.loads(output.decode("utf-8"))

    print(f"{utils_cheat.now()} - manalyze scan complete")
    # print("manalyze scan complete")

    serialised_output_dict = converter.serialize(output_dict[file_path])

    return serialised_output_dict  # [file_path]


file_dir = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    file_dir_split = os.path.split(file_dir)
    sample_dir = os.path.join(file_dir_split[0], "sample")
    sample_file_path = os.path.join(sample_dir, "Setup.exe")

    manalyze_dict = manalyze(sample_file_path)

    # pprint(manalyze_dict, indent=4)

    report_dir = os.path.join(file_dir_split[0], "reports")
    if not os.path.isdir(report_dir):
        os.makedirs(report_dir)
    report_file = os.path.join(report_dir, "manalyze.json")
    utils_cheat.create_json_file(report_file, manalyze_dict)

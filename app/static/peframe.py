"""
sudo add-apt-repository ppa:remnux/stable
sudo apt-get update
sudo apt install peframe
"""
# import utils
import subprocess
from pprint import pprint
import json

def peframe(file_path):
    output = subprocess.check_output(["peframe", "--json", file_path])
    output_dict = json.loads(output.decode("utf-8"))

    pprint(output_dict, indent=4)

    return output_dict

if __name__ == '__main__':
    file_path = "/home/andy/Desktop/Setup.exe"
    peframe(file_path)

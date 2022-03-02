from datetime import datetime
import json
import configparser


def get_config(config_file_path):
    config = configparser.ConfigParser()
    config.read(config_file_path)

    return config


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_json_file(json_file_path, json_data):
    with open(json_file_path, "w") as f:
        json.dump(json_data, f, indent=4)


def json_file_to_dict(json_file_path):
    with open(json_file_path, "r") as f:
        data = json.load(f)

    return data

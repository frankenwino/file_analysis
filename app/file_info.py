# -*- coding: utf-8 -*-

import hashlib
import subprocess
import json
# import sys
# import logging
import os
# from pprint import pprint
import magic
# import osslsigncode
import certificate_checker as certificate_checker


class FileInfo(object):
    """docstring for ExifTool."""
    def __init__(self, file_path):
        self.file_path = file_path
        self.exiftool = "/usr/bin/exiftool"
        self.md5sum = "/usr/bin/md5sum"

        try:
            self.output = subprocess.check_output([self.exiftool, "-j", self.file_path])
            self.exiftool_output_dict = json.loads(self.output.decode('utf-8'))[0]
            # pprint(self.exiftool_output_dict)
        except subprocess.CalledProcessError:
            self.exiftool_output_dict = None
        # pprint(self.exiftool_output_dict)

    def none_checker(self, none_item):
        self.none_item = str(none_item).strip()
        if len(self.none_item) == 0:
            self.none_item = None

        return self.none_item

    def pe_type(self):
        if self.exiftool_output_dict is not None:
            try:
                self.pe_type_info = self.none_checker(self.exiftool_output_dict["PEType"])
            except KeyError:
                self.pe_type_info = None
        else:
            self.pe_type_info = None

        return self.pe_type_info

    def mime_type(self):
        return magic.from_file(self.file_path, mime=True)

    def file_type(self):
        """
        e.g. PDF document, version 1.2
        """
        return magic.from_file(self.file_path)  # magic.from_buffer(open(self.file_path, encoding="utf8", errors='ignore').read(1024))

    def product_name(self):
        if self.exiftool_output_dict is not None:
            try:
                self.product_name_info = self.none_checker(self.exiftool_output_dict["ProductName"])
            except KeyError:
                self.product_name_info = None
        else:
            self.product_name_info = None

        return self.product_name_info

    def original_file_name(self):
        if self.exiftool_output_dict is not None:
            try:
                self.original_file_name_info = self.none_checker(self.exiftool_output_dict["OriginalFileName"])
            except KeyError:
                self.original_file_name_info = None
        else:
            self.original_file_name_info = None

        return self.original_file_name_info

    def company_name(self):
        if self.exiftool_output_dict is not None:
            try:
                self.company_name_info = self.none_checker(self.exiftool_output_dict["CompanyName"])
            except KeyError:
                self.company_name_info = None
        else:
            self.company_name_info = None

        return self.company_name_info

    def product_version(self):
        if self.exiftool_output_dict is not None:
            try:
                self.product_version_info = self.none_checker(self.exiftool_output_dict["ProductVersionNumber"])
            except KeyError:
                self.product_version_info = None
        else:
            self.product_version_info = None

        return self.product_version_info

    def object_file_type(self):
        if self.exiftool_output_dict is not None:
            try:
                self.object_file_type_info = self.none_checker(self.exiftool_output_dict["ObjectFileType"])
            except KeyError:
                self.object_file_type_info = None
        else:
            self.object_file_type_info = None

        return self.object_file_type_info

    def extension(self):
        if self.exiftool_output_dict is not None:
            try:
                self.extension_info = self.none_checker(self.exiftool_output_dict["FileTypeExtension"])
            except KeyError:
                self.extension_info = None
        else:
            self.extension_info = None

        return self.extension_info

    def file_size(self):
        return os.path.getsize(self.file_path)

    def md5(self):
        self.BLOCKSIZE = 65536
        self.hasher = hashlib.md5()
        with open(self.file_path, 'rb') as self.afile:
            self.buf = self.afile.read(self.BLOCKSIZE)
            while len(self.buf) > 0:
                self.hasher.update(self.buf)
                self.buf = self.afile.read(self.BLOCKSIZE)
        return self.hasher.hexdigest()

    def cert_check(self):
        self.cert = certificate_checker.check_cert(self.file_path)
        return self.cert

    def all_file_info(self):

        return {
            "pe_type": self.pe_type(),
            "file_type": self.file_type(),
            "mime_type": self.mime_type(),
            "product_name": self.product_name(),
            "original_file_name": self.original_file_name(),
            "company_name": self.company_name(),
            "product_version": self.product_version(),
            "object_file_type": self.object_file_type(),
            "extension": self.extension(),
            "md5": self.md5(),
            "certificate_subject": self.cert_check(),
            "size": os.path.getsize(self.file_path)
            }

    def all_file_info_not_none(self):
        all_info_dict = {}

        self.pe_type_info = self.pe_type()
        self.file_type = self.file_type()
        self.mime_type = self.mime_type()
        self.product_name = self.product_name()
        self.original_file_name = self.original_file_name()
        self.company_name = self.company_name()
        self.product_version = self.product_version()
        self.object_file_type = self.object_file_type()
        self.extension = self.extension()
        self.md5 = self.md5()
        # if self.mime_type not in config.compressed_file_mime_types:
        #     self.md5 = self.md5()
        # else:
        #     self.md5 = None
        self.certificate_subject = self.cert_check()
        self.size = os.path.getsize(self.file_path)

        all_info_dict["file_path"] = self.file_path

        if self.pe_type_info is not None:
            all_info_dict["pe_type"] = self.pe_type_info
        else:
            pass

        if self.file_type is not None:
            all_info_dict["file_type"] = self.file_type
        else:
            pass

        if self.mime_type is not None:
            all_info_dict["mime_type"] = self.mime_type
        else:
            pass

        if self.certificate_subject is not None:
            all_info_dict["certificate_subject"] = self.certificate_subject
        else:
            pass

        if self.product_name is not None:
            all_info_dict["product_name"] = self.product_name
        else:
            pass

        if self.original_file_name is not None:
            all_info_dict["original_file_name"] = self.original_file_name
        else:
            pass

        if self.company_name is not None:
            all_info_dict["company_name"] = self.company_name
        else:
            pass

        if self.product_version is not None:
            all_info_dict["product_version"] = self.product_version
        else:
            pass

        if self.object_file_type is not None:
            all_info_dict["object_file_type"] = self.object_file_type
        else:
            pass

        if self.extension is not None:
            all_info_dict["extension"] = self.extension
        else:
            pass

        if self.md5 is not None:
            all_info_dict["md5"] = self.md5
        else:
            pass

        if self.size is not None:
            all_info_dict["size"] = self.size
        else:
            pass

        return all_info_dict

# logger = logging.getLogger(__name__)
# this_script_name = sys.argv[0]
# log_file_name = os.path.join(
#     os.getcwd(),
#     log_file_name_generator.logfile_name_generator(this_script_name)
#     )
# logging.basicConfig(
#     filename=log_file_name,
#     filemode="w",
#     format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
#     datefmt='%Y-%m-%d %I:%M:%S %p',
#     level=logging.INFO
#     )


if __name__ == "__main__":
    pass

    # from pprint import pprint
    # file_path = "/home/downloads/WCInstaller(site).exe"
    # fileinfo_object = FileInfo(file_path)
    # pprint(fileinfo_object.all_file_info_not_none())

# -*- coding: utf-8 -*-
import subprocess
import magic
import os
import signal


def osslsigncode_installed():
    """
    Checks if osslsigncode is installed. If not, an error is raised.

    Returns
        True        Only returned if osslsigncode is installed.
    """
    try:
        output = subprocess.check_output(["which", "osslsigncode"]).decode().strip()

        return True

    except subprocess.CalledProcessError as e:
        error_message = "osslsigncode not installed. sudo apt-get install openssl and sudo apt-get install osslsigncode"
        raise OSError(error_message)


def check_file_type(file_path):
    """Checks file's file type.

    Arguments
        file_path       The file path of the file to be checked.
                        string

    Returns
        file_type       The file type of the file being checked.
                        string
    """
    file_type = magic.from_buffer(open(file_path, "rb").read(1024)).strip()

    return file_type

def is_pe(file_path):
    """
    Checks is a file's file type string starts with "PE".

    Arguments
        file_path       The file path of the file to be checked.
                        string

    Returns
        True | False
    """
    file_type = check_file_type(file_path)
    if file_type is not None and file_type.startswith("PE"):
        return True
    else:
        return False


def timeout_handler(signum, frame):
    signal_error_message = "Signal handler called with signal {}".format(signum)
    too_long_error_message = "osslsigncode taking too long to respond. It force quit after {} seconds. Probably hanging.".format(osslsigncode_timeout_length)
    os_error_message = "{} {}".format(too_long_error_message, signal_error_message)
    print(os_error_message)

    raise OSError(os_error_message)


def osslsigncode_verify(file_path):
    """
    Executes command "osslsigncode verify <file_path>"

    Arguments
        file_path               Path of the file to use in the command.
                                string

    Returns
        osslsigncode_output     Output of the command
                                string
                OR
        None                    ...when an error occurs running the command.
                                nonetype
    """
    if is_pe(file_path) and os.path.isfile(file_path):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(osslsigncode_timeout_length)
        try:
            osslsigncode_output = subprocess.check_output(
                [
                    "osslsigncode",
                    "verify",
                    file_path
                    ]
                ).decode().strip()
            signal.alarm(0)
            return osslsigncode_output
        except (OSError, subprocess.CalledProcessError) as e:
            signal.alarm(0)
            #fails.append(file_path)
            return None


    else:
        return None

def parse_subject_line(subject_line):
    subject_name_list = []
    split_subject_line = subject_line.split("/")

    for subject_line in split_subject_line:
        if subject_line.startswith("O="):# or subject_line.startswith("CN="):
            subject_name = subject_line.split("=")[-1]
            subject_name_list.append(subject_name)

    subject_name_list = list(set(subject_name_list))

    return subject_name_list


def get_total_signers(split_output):
    split_output = split_output
    total_signers = 0
    signers_list_index = None
    for i in split_output:
        if i.startswith("Number of signers"):
            total_signers = int(i.split(":")[-1].strip())
            signers_list_index = split_output.index(i)
            # print("Signers: {} index: {}".format(total_signers, split_output.index(i)))
            break
    return total_signers, signers_list_index


def parse_osslsigncode_verify_output(osslsigncode_output):
    subjects = []

    if osslsigncode_output is not None:
    # Get total amount of signers from osslsigncode output
        split_sslsigncode_output = osslsigncode_output.split("\n")
        total_signers, signers_list_index = get_total_signers(split_sslsigncode_output)

        # Iterate through all signers subject info
        if signers_list_index is not None:
            subject_index = signers_list_index + 2
            for x in range(total_signers):
                subject_line = split_sslsigncode_output[subject_index].strip()
                subject_name_list = parse_subject_line(subject_line)
                for subject_name in subject_name_list:
                    subjects.append(subject_name)
                subject_index += 3

            subjects = list(set(subjects))

            if len(subjects) == 1:
                cert_subject = subjects[0]

            elif len(subjects) > 1:
                cert_subject = ",".join(subjects)

            else:
                cert_subject = None
        else:
            cert_subject = None
    else:
        cert_subject = None

    return cert_subject


def check_cert(file_path):
    if osslsigncode_installed():
        osslsigncode_output = osslsigncode_verify(file_path)
        cert_subject = parse_osslsigncode_verify_output(osslsigncode_output)

        return cert_subject
    else:
        sys.exit(0)

osslsigncode_timeout_length = 5

if __name__ == "__main__":
    pass

    # from pprint import pprint
    # import texttable as tt
    # tab = tt.Texttable()
    # headings = ['File','Cert','File Type']
    # tab.header(headings)

    # print(file_path)
    # cert = check_cert(file_path)
    # result = {
    #     "file_type": check_file_type(file_path),
    #     "cert": cert,
    #     "file_name": os.path.basename(file_path)
    #     }
    # pprint(result)

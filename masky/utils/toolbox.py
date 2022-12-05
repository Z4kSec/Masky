import socket
import os
from pathlib import Path


def is_valid_file(file_path):
    if file_path == "":
        return False
    elif not Path(file_path).is_file():
        return False
    elif not os.access(file_path, os.R_OK):
        return False
    return True


def is_valid_output_folder(folder_path):
    try:
        if folder_path == "":
            return False
        elif not Path(folder_path).is_dir():
            return False
        elif not os.access(folder_path, os.W_OK):
            return False
    except Exception:
        return False
    return True


def scan_port(host, port=445):
    s = socket.socket()
    s.settimeout(2)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        code = s.connect_ex((host, port))
        s.close()
        return code == 0
    except socket.error:
        return False


class FakeBufferReader:
    string = None

    def get_string(max_buff_size):
        if FakeBufferReader.string:
            tmp_string = FakeBufferReader.string
            FakeBufferReader.string = None
            return tmp_string
        else:
            return ""

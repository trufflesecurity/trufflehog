import math
from bcolors import BColors as bc
from datetime import datetime as dt

class Utility(object):
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    HEX_CHARS = "1234567890abcdefABCDEF"

    @classmethod
    def shannon_entropy(cls, data, iterator):
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        """
        if not data:
            return 0
        entropy = 0
        for x in (ord(c) for c in iterator):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    @classmethod
    def get_strings_of_set(cls, word, char_set, threshold=20):
        count = 0
        letters = ""
        strings = []
        for char in word:
            if char in char_set:
                letters += char
                count += 1
            else:
                if count > threshold:
                    strings.append(letters)
                letters = ""
                count = 0
        if count > threshold:
            strings.append(letters)
        return strings

    @classmethod
    def examine_string(cls, in_string, str_type):
        str_type_ref = {"b64": Utility.BASE64_CHARS,
                        "hex": Utility.HEX_CHARS}
        entropy_threshold_ref = {"b64": 4.5,
                                 "hex": 3}
        entropy = Utility.shannon_entropy(in_string, str_type_ref[str_type])
        if entropy > entropy_threshold_ref[str_type]:
            alert_string = str(bc.WARNING + in_string + bc.ENDC)
            return alert_string
        else:
            return in_string

    @classmethod
    def print_alert(cls, prev_commit, branch_name, printableDiff):
        prev_commit_date = dt.fromtimestamp(prev_commit.committed_date)
        commit_time = Utility.format_time(prev_commit_date)
        print(bc.OKGREEN + "Date: " + commit_time + bc.ENDC)
        print(bc.OKGREEN + "Branch: " + branch_name + bc.ENDC)
        print(bc.OKGREEN + "Commit: " + prev_commit.message + bc.ENDC)
        print(printableDiff)

    @classmethod
    def format_time(cls, dt_obj):
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S')

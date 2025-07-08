#!/usr/bin/env python3.6

import argparse
import sys
import re
from datetime import datetime

date_regex_1 = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"  # Format: 2025-01-08 12:21:55
date_regex_2 = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{2}:\d{2})?"  # Format: 2025-01-09T00:07:43.587463+01:00

def main():
    parser = argparse.ArgumentParser(
        description="Filter to unify time formats between log lines: reads from filename or stdin if no filename if provided."
    )
    parser.add_argument(
        "filename",
        nargs="?",
        type=argparse.FileType('r'),
        default=sys.stdin,
        help="Input filename to read (default: stdin)"
    )

    args = parser.parse_args()

#    for line in sys.stdin:
    for line in args.filename:
        line = line.strip()
        if re.match(date_regex_1, line):
            # 2025-01-08 12:21:55
            try:
                iso_date_string, rest = re.match(rf"({date_regex_1}) (.*)", line).groups()
                date_obj = datetime.strptime(iso_date_string, "%Y-%m-%d %H:%M:%S")
                formatted_date_string = date_obj.strftime("%b %d %H:%M:%S")
                print(formatted_date_string, rest)
            except ValueError:
                pass
        elif re.match(date_regex_2, line):
            # 2025-01-09T00:07:43.587463+01:00
            try:
                iso_date_string, rest = line.strip().split(" ", 1)
                iso_date_string = iso_date_string.split('+')[0]
                date_obj = datetime.strptime(iso_date_string, "%Y-%m-%dT%H:%M:%S.%f")
                formatted_date_string = date_obj.strftime("%b %d %H:%M:%S.%f")[:-3]  # Strip to milliseconds
                print(formatted_date_string, rest)
            except ValueError:
                pass
        else:
            print(line)


if __name__ == "__main__":
    main()

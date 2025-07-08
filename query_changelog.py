#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import re
import subprocess
import sys

from collections import OrderedDict
from datetime import datetime
from pprint import pformat

__version__ = "1.0"

date_re = re.compile(r"\* (\w{3} \w{3} \d{2} \d{4})")


def clean_bullet(line):
    return line.strip()[2:] if line.strip().startswith("- ") else line.strip()


def extract_date(key):
    m = date_re.search(key)
    if m:
        try:
            return datetime.strptime(m.group(1), "%a %b %d %Y")
        except ValueError:
            pass
    return datetime.min # fallback so it sorts last


def get_rpm_changes(filename, pattern, stop_patterns=None, attempts=None, debug=False):
    results = OrderedDict()
    sorted_results = None

    if attempts and debug:
        logging.debug("[ARGS] Pattern: %s", pattern)
        logging.debug("[ARGS] Attempts: %d", attempts)

    if stop_patterns and debug:
        logging.debug("[STOP] Patterns found:")
        logging.debug("\n%s", pformat(stop_patterns))

    try:
        output = subprocess.check_output(["rpm", "--changelog", "-qp", filename], universal_newlines=True)
    except subprocess.CalledProcessError as e:
        logging.error("Failed to read changelog from %s: %s", filename, e)
        return None

    paragraphs = re.split(r'\n\s*\n', output, flags=re.MULTILINE)
    del output # free mem

    matched_stop = None

    for para in paragraphs:
        if attempts and len(results.keys()) >= attempts:
            break

        lines = para.strip().splitlines()
        if not lines:
            continue

        firstline = lines[0]
        found_stop = False

        for line in lines[1:]:
            # Stop if any stop pattern matches
            if stop_patterns:
                for pat in stop_patterns:
                    if re.search(re.escape(pat), line, re.IGNORECASE):
                        matched_stop = pat
                        if debug:
                            logging.debug("[MATCH] Pattern found: %s", pat)
                        found_stop = True
                        break
                if found_stop:
                    break

            # Match the main search pattern
            if re.search(pattern, line, re.IGNORECASE):
                clean_line = clean_bullet(line)
                results.setdefault(firstline, []).append(clean_line)

        if found_stop:
            break

    # Sort results by key date descending
    if results:
        sorted_results = OrderedDict(
            sorted(results.items(), key=lambda item: extract_date(item[0]), reverse=True)
        )

    if attempts:
        if debug and sorted_results:
            logging.debug("[OLD] Changelog entries extracted:")
            logging.debug("\n%s", pformat(sorted_results))
        return [line for lines in sorted_results.values() for line in lines]
    elif debug and sorted_results:
            logging.debug("[NEW] Changelog entries since last match:")
            logging.debug("\n%s", pformat(sorted_results))

    return sorted_results


def main():
    parser = argparse.ArgumentParser(
        description="Search and compare changelog entries between two RPM packages",
        epilog=(
            "⚠ LIMITATION: This tool compares RPM changelogs based on entry order, "
            "not semantic diffing or patch ancestry.\n"
            "A change in the newer package may affect functionality even if it's older "
            "than the latest matching entry from the older package.\n"
            "Use with caution — not all impactful changes may be detected."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "pattern",
        help="Pattern to search (regex); e.g. 'xfs:)'"
    )
    parser.add_argument(
        "-o", "--old-rpm",
        required=True,
        help="Older RPM package filename"
    )
    parser.add_argument(
        "-n", "--new-rpm",
        required=True,
        help="Newer RPM package filename"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="debug reporting"
    )
    parser.add_argument(
        "-a", "--attempts",
        type=int,
        default=3,
        help="Number of entries to consider for old RPM"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s " + __version__,
        help="Show program version and exit"
    )

    args = parser.parse_args()

    pattern = args.pattern
    debug = args.debug
    attempts = args.attempts

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    new_changes = {}
    old_changes = get_rpm_changes(args.old_rpm, pattern, attempts=attempts, debug=debug)

    if old_changes:
        new_changes = get_rpm_changes(args.new_rpm, pattern, stop_patterns=old_changes, debug=debug)
    else:
        print("No matching changes found in old RPM!", file=sys.stderr)

    if new_changes and not debug:
        print("# The effort to find changes in newer changelog is the following:")
        for key, lines in new_changes.items():
            print("{}:".format(key))
            for l in lines:
                print("  - ", l)


if __name__ == "__main__":
    main()

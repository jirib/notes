#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "requests",
#     "rpm_vercmp",
# ]
# ///

import argparse
import functools
import json
import logging
import os
import re
import requests
import rpm_vercmp as rpm
import sys

from itertools import groupby
from itertools import product
from operator import itemgetter
from packaging.version import parse as vparse

HEADERS = {
    'accept': 'application/json',
    'Accept': 'application/vnd.scc.suse.com.v4+json'
}

PRODUCT_IDENTIFIER_REGEX = re.compile(r'^[A-Za-z0-9_-]+/\d+(\.\d+)?/\w+$')

URL_PREFIX = 'https://scc.suse.com/api/package_search'


class MyLogger(logging.Logger):
    def debug_json(self, label: str, data) -> None:
        self.debug(
            "%s:\n%s",
            label,
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            ),
        )

logging.setLoggerClass(MyLogger)

log = logging.getLogger(__name__)


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO

    logging.setLoggerClass(MyLogger)

    logging.basicConfig(
        level=level,
        format='%(levelname)s %(name)s: %(message)s',
        stream=sys.stderr
    )


def parse_arguments() -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = argparse.ArgumentParser(
        description="CLI SCC package search"
    )

    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug output (default: False)'
    )

    parser.add_argument(
        '-x', '--exact',
        action='store_true',
        help='Enable exact match (default: False)'
    )

    parser.add_argument(
        '-P', '--list-products',
        action='store_true',
        help='List available products and exit (default: False)'
    )

    parser.add_argument(
        "identifier",
        nargs="?",  # optional to allow --list-products to work without it
        help="Product identifier (eg. SLES_SAP/15.6/x86_64)"
    )

    parser.add_argument(
        "pattern",
        nargs="?",  # optional to allow --list-products to work without it
        help="Package string to query (eg. kernel-default)"
    )

    args = parser.parse_args()
    return parser, args


def validate_arguments(
        parser: argparse.ArgumentParser,
        args: argparse.Namespace
) -> None:
    """
    Validates the command-line arguments and exits with an error message if
    they are invalid.
    """
    log.debug("Starting validate_arguments function")
    log.debug("args=%r", vars(args))

    if args.list_products and (args.identifier or args.pattern):
        log.error(
            "'identifier' and 'pattern' arguments should not be provided "
            "when '--list-products' is used."
        )
        parser.print_help()
        sys.exit(2)

    if not args.list_products:

        if not args.identifier or not args.pattern:
            log.error(
                "'identifier' and 'pattern' arguments are required"
            )
            parser.print_help()
            sys.exit(2)

        if not PRODUCT_IDENTIFIER_REGEX.match(args.identifier):
            log.error(
                "Invalid product identifier format: %r. Expected format is "
                "something like 'SLES_SAP/15.7/x86_64'.",
                args.identifier
            )
            parser.print_help()
            sys.exit(2)


def get_products(list_products_identifier: bool) -> tuple:
    """
    Fetches the list of products from the API and returns it as a tuple.
    """
    log.debug("Starting get_products function")

    query_url = URL_PREFIX + '/products'

    try:
        response = requests.get(query_url, headers=HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error("Request failed", exc_info=True)
        sys.exit(1)
    finally:
        log.debug(
            "Request to %r completed with status code %s",
            query_url,
            response.status_code
        )

    products = tuple(response.json().get('data', []))
    products = tuple(  # sort products by identifier
        sorted(
            products,
            key=itemgetter('identifier'),
        )
    )

    log.debug("Received %d products from API", len(products))
    log.debug_json("Products data:", products)

    if list_products_identifier:
        for product in products:
            print(product['identifier'])
        sys.exit(0)

    return products


def get_id_by_identifier(identifier: str, products: tuple) -> int:
    """
    Finds the product ID corresponding to the given identifier in the list of
    products.
    """
    log.debug("Starting get_id_by_identifier function")

    for product in products:
        log.debug("Checking product: %s", product['identifier'])

        if product['identifier'] == identifier:
            product_id = int(product['id'])

            log.debug(
                "Found product ID %r for identifier %r",
                product_id,
                identifier
            )
            return product_id

    raise ValueError(f'Identifier "{identifier!r}" not found')


def split_version_release(version_release: str) -> tuple[str, str]:
    """
    Splits a version-release string into its version and release components.
    """
    log.debug("Starting split_version_release function")

    version, sep, release = version_release.partition("-")

    return version, release


def compare_versions_release(a: str, b: str) -> int:
    """
    Compares two version-release strings using RPM version comparison rule.
    """
    log.debug("Starting compare_versions_release function")

    a_version, a_release = split_version_release(a)
    b_version, b_release = split_version_release(b)

    version_cmp = rpm.vercmp(a_version, b_version)
    if version_cmp != 0:
        return version_cmp

    return rpm.vercmp(a_release, b_release)


def compare_packages(pkg1: dict, pkg2: dict) -> int:
    """
    Compares two package dictionaries based on their names and
    version-releases.
    """
    log.debug("Starting compare_packages function")

    name_cmp = (pkg1['name'] > pkg2['name']) - (pkg1['name'] < pkg2['name'])
    if name_cmp != 0:
        return name_cmp

    version_cmp = compare_versions_release(
        pkg1['version_release'],
        pkg2['version_release']
    )

    if version_cmp != 0:
        return version_cmp

    return(pkg1['identifier'] > pkg2['identifier']) - \
        (pkg1['identifier'] < pkg2['identifier'])


def search_package(
        product_id: int,
        pattern: str,
        exact: bool = False
) -> tuple:
    """
    Searches for packages matching the given pattern and product ID, and
    returns a sorted tuple of results.
    """
    log.debug("Starting search_package function")

    result  = []
    query_url = URL_PREFIX + '/packages'

    params = {
        'product_id': product_id,
        'query': pattern
    }

    try:
        response = requests.get(query_url, headers=HEADERS, params=params)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error("Request failed", exc_info=True)
        sys.exit(1)
    finally:
        log.debug(
            "Request to '%s' completed with status code '%d'",
            query_url,
            response.status_code
        )

    data = tuple(response.json().get('data', []))

    if not data:
        return ()

    log.debug(
        "Received %d packages from API for product_id %d and query '%s'",
        len(data),
        product_id,
        pattern
    )
    log.debug_json("Packages data", data)

    result = []
    for pkg in data:
        log.debug("Processing package: %s", pkg['name'])
        if exact and pkg['name'] != pattern:  # exact match not met
            # TODO: improve logging here
            log.debug(
                "Skipping package '%s' due to exact match requirement",
                pkg['name']
            )
            continue

        for product in pkg['products']:
            result.append({
                'name': pkg['name'],
                'version_release': f"{pkg['version']}-{pkg['release']}",
                'identifier': product['identifier']
                })

        sorted_by_name = sorted(result, key=lambda x: x["name"])

        sorted_output = tuple(
            item
            for _, group in groupby(sorted_by_name, key=lambda x: x["name"])
            for item in sorted(group, key=functools.cmp_to_key(compare_packages))
        )

        log.debug_json("Sorted output", sorted_output)

    try:
        return sorted_output if sorted_output else ()
    except NameError:
        return ()


def main() -> int:
    parser, args = parse_arguments()

    setup_logging(args.debug)

    validate_arguments(parser, args)

    log.debug("Starting main function")

    try:
        identifier = args.identifier
        pattern = args.pattern
        exact = args.exact

        products = get_products(args.list_products)
        product_id = get_id_by_identifier(identifier, products)

        sorted_output = search_package(product_id, pattern, exact)

        if sorted_output:
            for pkg in sorted_output:
                print(  # TODO: improve output formatting here
                    f"{pkg['name']}-{pkg['version_release']} {pkg['identifier']}"
                )
        else:
            log.info("No packages found matching the criteria.")

        return 0

    except ValueError as exc:
        log.error("%s", exc)
        return 1

    except Exception:
        log.error("Unexpected error", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
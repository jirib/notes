#!/usr/bin/env python3

import argparse
import os
import requests
import sys

from packaging.version import parse as vparse

headers = {
    'accept': 'application/json',
    'Accept': 'application/vnd.scc.suse.com.v4+json'
}
url_prefix = 'https://scc.suse.com/api/package_search'


def get_id_by_identifier(identifier):
    product = None
    query_url = url_prefix + '/products'

    try:
        response = requests.get(query_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Request failed: {}".format(e), file=sys.stderr)
        sys.exit(1)

    data = response.json().get('data', [])

    for product in data:
        if product['identifier'] == identifier:
            product = product['id']
            return product

    try:
        raise ValueError('identifier "{}" not found'.format(identifier))
    except ValueError as e:
        print('Error: {}'.format(e), file=sys.stderr)
        sys.exit(1)


def search_package(product_id, package, exact):
    output = []
    query_url = url_prefix + '/packages'

    params = {
        'product_id': product_id,
        'query': package
    }

    try:
        response = requests.get(query_url, headers=headers, params=params)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Request failed: {}".format(e), file=sys.stderr)
        sys.exit(1)

    data = response.json().get('data', [])

    if data:  # it might be empty if package pattern is bogus
        for pkg in data:
            if exact and pkg['name'] != package:  # exact match not met
                continue

            for product in pkg['products']:
                output.append({
                    'name': pkg['name'],
                    'version_release': '{}-{}'.format(pkg['version'], pkg['release']),
                    'identifier': product['identifier']
                })

        sorted_output = sorted(
            output,
            key=lambda x: (
                x['name'],
                vparse(x['version_release']),
                vparse(x['identifier'])
            )
        )

    try:
        return sorted_output if sorted_output else []
    except NameError:
        return []


def main():
    parser = argparse.ArgumentParser(
        description="CLI SCC package search"
    )
    parser.add_argument(
        "identifier",
        help="Product identifier (eg. SLES_SAP/15.6/x86_64)"
    )
    parser.add_argument(
        "pattern",
        help="Package string to query (eg. kernel-default)"
    )
    parser.add_argument(
        '-x', '--exact',
        action='store_true',
        help='Enable exact match (default: False)'
    )

    args = parser.parse_args()

    product = args.identifier
    package = args.pattern
    exact = args.exact

    product_id = get_id_by_identifier(product)
    sorted_output = search_package(product_id, package, exact)

    if sorted_output:
        for pkg in sorted_output:
            print('{}-{} {}'.format(pkg['name'], pkg['version_release'], pkg['identifier']))


if __name__ == "__main__":
    main()

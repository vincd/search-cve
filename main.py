# -*- coding: utf-8 -*-

import io
import gzip
import json
import datetime

import requests
import click

CVE_DB_FILE = 'cve_db.json'
# CVE start in 1999 bute there is not records until 2002 in the nvd database
MIN_YEAR = 2002
MAX_YEAR = datetime.datetime.now().year



@click.group()
@click.version_option('beta')
def cli():
    pass


def download_dbs():
    for year in range(MIN_YEAR, MAX_YEAR + 1):
        url = f'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{year}.json.gz'
        db_file = f'nvdcve-1.0-{year}.json'

        click.echo(f'... downloading year {year} to {db_file}')
        # Download the gzip file as a stream
        r = requests.get(url, stream=True)

        with gzip.GzipFile(fileobj=io.BytesIO(r.content), mode='rb') as fo:
            with open(db_file, 'wb') as fd:
                while True:
                    chunk = fo.read(1024)
                    if not chunk:
                        break
                    fd.write(chunk)


def parse_item(item):
    """
    Parse a CVE item from the NVD database
    """

    parsed_items = {}

    cve = item.get('cve', {})
    CVE_data_meta = cve.get('CVE_data_meta', {})
    ID = CVE_data_meta.get('ID', '')
    parsed_items['id'] = ID

    affects = cve.get('affects', {})
    vendor = affects.get('vendor', {})
    vendor_datas = vendor.get('vendor_data', [])
    parsed_items['vendors'] = vendor_datas

    return parsed_items

@cli.command(help='Download database and save it locally.')
@click.option('-d', '--db', 'db_path', type=str, required=False, default=CVE_DB_FILE)
def update(db_path):
    db = []

    click.echo('Download db files from https://nvd.nist.gov/ ...')
    download_dbs()

    click.echo('Parse db files ...')
    for year in range(MIN_YEAR, MAX_YEAR + 1):
        db_file = f'nvdcve-1.0-{year}.json'
        with open(db_file, 'r') as fd:
            db_year = json.loads(fd.read())
            items = db_year.get('CVE_Items', [])
            for item in items:
                db.append(parse_item(item))

    click.echo(f'Save parsed db to {db_path} ...')
    with open(db_path, 'w') as fd:
        fd.write(json.dumps(db))


@cli.command(help='Search a CVE by product name and version.')
@click.option('-d', '--db', 'db_path', type=str, required=False, default=CVE_DB_FILE)
@click.option('-p', '--product', 'search_product', type=str, required=True)
@click.option('-v', '--version', 'search_version', type=str, required=True)
@click.option('-a', '--all-matches', 'all_matches', is_flag=True)
def search(db_path, search_product, search_version, all_matches):
    with open(db_path, 'r') as fd:
        db = json.loads(fd.read())

    results = []

    for item in db:
        vendors = item.get('vendors')
        for vendor_data in vendors:
            # vendor_name = vendor_data.get('vendor_name', '')
            product = vendor_data.get('product', {})
            product_datas = product.get('product_data', [])

            for product_data in product_datas:
                product_name = product_data.get('product_name', '')

                if product_name.lower() == search_product:
                    version = product_data.get('version', {})
                    version_datas = version.get('version_data', [])

                    for version_data in version_datas:
                        version_value = version_data.get('version_value', '')
                        version_affected = version_data.get('version_affected', '')

                        if version_value == search_version or (all_matches and version_value == '*'):
                            results.append(item.get('id', ''))

    click.echo(json.dumps(results, indent=4, sort_keys=True))


if __name__ == '__main__':
    cli()

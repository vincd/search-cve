# Search CVE

Search a CVE based on a product name and version


## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Update the CVE database with the following command:

```bash
python main.py update
Download db files from https://nvd.nist.gov/ ...
... downloading year 2002 to nvdcve-1.0-2002.json
...
... downloading year 2020 to nvdcve-1.0-2020.json
Parse db files ...
Save parsed db to cve_db.json ...
```


## How to use

```bash
python main.py search -p {PRODUCT_NAME} -v {PRODUCT_VERSION}
```

This will output a JSON list of CVE:

```bash
python main.py search -p php -v 7.3.1
[
    "CVE-2019-11034",
    ...
    "CVE-2020-7067"
]
```

For old CVE, the database doesn't contain specific versions but a `*`. You can
include theses results by passing the `-a/--all-matches` argument.


## License

MIT
The `nvdcve-1.0-YYYY.json` files come from the official [https://nvd.nist.gov](https://nvd.nist.gov).

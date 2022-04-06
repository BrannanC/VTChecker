# Virus Total Checker

Parses files for URLs, IPs and file hashes to check them against Virus Total. Any query with no malicious results are stored in `known_good.txt`. Any query found in `known_good.txt` won't be checked.

There are some limitations to the way this parses files. If there's a specific format you need to parsed simply extend `VT_Parser` and implement the `get_queries` method. Then add the class to the drive method of `VT_Checker`. Feel free to fork or make PRs.

## Installation

Clone this repository then install required libraries. It's just `requests` and `aiohttp`.

```bash
pip install -r requirements.txt
```

This project also relies on a `keys.py` file that holds Virus Total API keys in a list named `keys`.

```python
keys = ["API key", "additional API key"]
```

## Usage

```
usage: python3 vt_checker.py filename [OPTIONS]

positional arguments:
  filename              Path to file to check

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file name
  -s, --silent          Silent Mode
  -v, --verbose         Verbose output
```

import argparse


def get_input_args():
    parser = argparse.ArgumentParser(
        description="Parses logs for VirusTotal query strings and checks for idications of compromise.",
        usage="python3 vt_checker.py filename [OPTIONS]"
    )

    parser.add_argument('filename', type=str,
                        help='Path to file to check')
    parser.add_argument('-o', "--output-file", type=str, help="Output file name")
    parser.add_argument('-s', "--silent", action='store_true', help="Silent Mode")
    parser.add_argument('-v', "--verbose", action='store_true', help="Verbose output")

    return parser.parse_args()

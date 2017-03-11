#!/venv/bin/python
import argparse

parser = argparse.ArgumentParser(description='Scan ports on a specified host.')
parser.add_argument('dhost', help="targets to scan in CIDR notation")
parser.add_argument('dport', help="ports to scan in single or range or comma=delimited")


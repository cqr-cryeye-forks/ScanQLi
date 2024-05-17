#!/usr/bin/python

import function
import requests
import time
import config
from termcolor import colored
import optparse_mooi
import optparse
import validators
import progressbar
import json
from operator import is_not
from functools import partial
import numpy
import os
import urllib.parse as urlparse  # Python3

def main():
    data = {"data": None}
    # Define parser
    examples_message = """\nExamples:
      python scanqli.py -u 'http://127.0.0.1/test/?p=news' -o output.log\n  python scanqli.py -u 'https://127.0.0.1/test/' -r -c '{"PHPSESSID":"4bn7uro8qq62ol4o667bejbqo3" , "Session":"Mzo6YWMwZGRmOWU2NWQ1N2I2YTU2YjI0NTMzODZjZDVkYjU="}'\n"""
    # logo_message = logo.chooselogo()

    parser = optparse.OptionParser(usage="python scanqli.py -u [url] [options]",
                                   epilog=examples_message,
                                   formatter=optparse_mooi.CompactHelpFormatter(align_long_opts=True, metavar_column=20))
    groupscan = optparse.OptionGroup(parser, "Scanning")
    groupoutput = optparse.OptionGroup(parser, "Output")

    groupscan.add_option('-u', "--url", action="store", dest="url", help="URL to scan", default=None)
    groupscan.add_option('-c', "--cookies", action="store", metavar="cookies", dest="cookies", help="Scan with given cookies", default=None, type=str)
    groupscan.add_option('-s', "--nosslcheck", action="store_true", dest="nosslcheck", help="Don't verify SSL certs")
    groupscan.add_option('-q', "--quick", action="store_true", dest="quick", help="Check only very basic vulns", default=None)
    groupscan.add_option('-r', "--recursive", action="store_true", dest="recursive", help="Recursive URL scan (will follow each href)", default=False)
    groupscan.add_option('-w', "--wait", action="store", metavar="seconds", dest="waittime", help="Wait time between each request", default=None, type=float)
    groupoutput.add_option('-v', "--verbose", action="store_true", dest="verbose", help="Display all tested URLs", default=False)
    groupoutput.add_option('-o', "--output", action="store", metavar="file", dest="output", help="Write outputs in file", default=None)
    parser.add_option_group(groupscan)
    parser.add_option_group(groupoutput)

    options, args = parser.parse_args()

    # Check requiered arg
    if not options.url and not options.urllist:
        parser.print_help()
        exit(0)

    # Check verbose args
    function.verbose = options.verbose

    # Cookies
    if options.cookies:
        function.cookies = json.loads(options.cookies)

    # NoSSLCheck
    if options.nosslcheck:
        function.verifyssl = False

    # Wait time
    if options.waittime:
        function.waittime = float(options.waittime)

    # Quick scan
    if options.quick:
        config.scantype = "quick"

    if options.url and validators.url(options.url):
        url = [options.url]

    # init config
    config.init()

    if data == {}:
        data_list = {
              "Error": "Nothing found in ScanQli"
            }
        output_filename = options.output
        function.CheckFilePerm(output_filename, data_list)
        exit(0)

    if options.recursive:
        baseurl = []
        for unit_url in url:
            if unit_url[-1:] != "/" and os.path.splitext(urlparse.urlparse(unit_url).path)[1] == "":
                unit_url = unit_url + "/"
            baseurl.append(unit_url)
            print("Base URL = " + unit_url)

        if len(baseurl) > 0:
            try:
                page_set = function.GetAllPages(baseurl)
            except TypeError as e:
                page_set = {}
        else:
            page_set = {}
        data_list = []
        for key, value in page_set.items():
            data = {"URL": key}
            data_list.append(data)
        print(str(len(page_set)) + " URLs founds")
        if page_set == {}:
            data_list = {
                  "Error": "Nothing found in ScanQli"
                }
        if str(len(page_set)) == "0":
            data_list = {
                  "Error": "Nothing found in ScanQli"
                }
        output_filename = options.output

        function.CheckFilePerm(output_filename, data_list)


if __name__ == '__main__':
    main()

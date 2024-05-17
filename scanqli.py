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
    groupscan.add_option('-U', "--urllist", action="store", metavar="file", dest="urllist", help="URL list to scan (one line by url)", default=None)
    groupscan.add_option('-i', "--ignore", action="append", metavar="url", dest="iurl", help="Ignore given URLs during scan", default=None)
    groupscan.add_option('-I', "--ignorelist", action="store", metavar="file", dest="iurllist", help="Ignore given URLs list (one line by url)", default=None)
    groupscan.add_option('-c', "--cookies", action="store", metavar="cookies", dest="cookies", help="Scan with given cookies", default=None, type=str)
    groupscan.add_option('-s', "--nosslcheck", action="store_true", dest="nosslcheck", help="Don't verify SSL certs")
    groupscan.add_option('-q', "--quick", action="store_true", dest="quick", help="Check only very basic vulns", default=None)
    groupscan.add_option('-r', "--recursive", action="store_true", dest="recursive", help="Recursive URL scan (will follow each href)", default=False)
    groupscan.add_option('-w', "--wait", action="store", metavar="seconds", dest="waittime", help="Wait time between each request", default=None, type=str)
    groupoutput.add_option('-v', "--verbose", action="store_true", dest="verbose", help="Display all tested URLs", default=False)
    groupoutput.add_option('-o', "--output", action="store", metavar="file", dest="output", help="Write outputs in file", default=None)
    parser.add_option_group(groupscan)
    parser.add_option_group(groupoutput)

    options, args = parser.parse_args()

    # Check requiered arg
    if not options.url and not options.urllist:
        parser.print_help()
        exit(0)
    elif options.url and validators.url(options.url):
        url = [options.url]
    elif options.urllist:
        text_file = open(options.urllist, "r")
        url = text_file.read().split('\n')
        url = filter(partial(is_not, ""), url)
        for infile in url:
            if not validators.url(infile):
                function.PrintError("-u " + infile, "Malformed URL. Please given a valid URL")
                data = {}
    else:
        function.PrintError("-u " + options.url, "Malformed URL. Please given a valid URL")
        data = {}

    # Check verbose args
    function.verbose = options.verbose

    # Check Banned URLs
    if options.iurl:
        for bannedurl in options.iurl:
            if validators.url(bannedurl):
                config.BannedURLs.append(bannedurl)
            else:
                function.PrintError("-i " + bannedurl, "Malformed URL. Please given a valid URL")
                data = {}


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
        for uniturl in url:
            if uniturl[-1:] != "/" and os.path.splitext(urlparse.urlparse(uniturl).path)[1] == "":
                uniturl = uniturl + "/"
            baseurl.append(uniturl)
            print("Base URL = " + uniturl)
        pageset = function.GetAllPages(baseurl)
        data_list = []
        for key, value in pageset.items():
            data = {"URL": key}
            data_list.append(data)
        print(str(len(pageset)) + " URLs founds")
        if pageset == {}:
            data_list = {
                  "Error": "Nothing found in ScanQli"
                }
        if str(len(pageset)) == "0":
            data_list = {
                  "Error": "Nothing found in ScanQli"
                }
        output_filename = options.output

        function.CheckFilePerm(output_filename, data_list)


if __name__ == '__main__':
    main()

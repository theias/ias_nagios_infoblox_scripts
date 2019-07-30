#!/usr/bin/python3

"""
# Author

Christopher Peterson (cspeterson@github) , Institute for Advanced Study

Refactored by mvanwinkleias for the purposes of investigating Python stuff

# Description

This script pulls all of the hosts from ipam, looks for the hosts with the 'nagios' extattr, and dumps them into a file for puppet/nagios to look at.

By default, this script will output a multi-line pretty-printed json document to STDOUT.


# Setup / Installation

This script looks for credentials in "~/.config/IAS/ipam_script_user.json",

  {
    "api_protocol" : "https",
    "api_uri" : "/wapi/v1.6/",
    "ipam_master" : "ipam-ha.example.com",
    "username" : "some_user",
    "password" : "some_password"
  }


# Dependencies

The script worked on Ubuntu 16.04 , and Springdale Linux 7 without
having to install additional packages.  But, if you find that a package is
required, which isn't part of a "standard build" for EL and Deb systems
please inform us.  We'll add it to the dependencies.


"""

from __future__ import print_function

import os
import syslog

import itertools
import json
import os
import requests
import socket
import sys
import getpass
from time import time, ctime
import argparse
import pprint

def load_ipam_credentials_from_file(filename):
    data = json.load(open(filename))
    
    data['api_url'] = "%s://%s/%s" % (
        data['api_protocol'],
        data['ipam_master'],
        data['api_uri']
    )
    
    return data

def fetch_ipam_records_host(session, api):

    write_log_info('Fetching host records.')
    ret = session.get(
        api
        + 'record:host?'
        + '&'.join([
            '_max_results=250000',
            '_return_fields=extattrs,name,ipv4addrs',
            'view=internal',
            '*nagios_notify=1'
        ])
    )
    if ret.status_code != 200:
        write_log_error_and_exit(
            'Error code {}. Quitting.'.format(ret.status_code),
            1
        )
    hosts_content = ret.content
    hosts = json.loads(hosts_content.decode('utf-8'))
    return hosts

def fetch_ipam_records_cname(session, api):
    # Also get cname records
    write_log_info('Fetching cname records.')
    ret = session.get(
        api
        + 'record:cname?'
        + '&'.join([
            '_max_results=250000',
            '_return_fields=extattrs,name,dns_canonical',
            'view=internal',
            '*nagios_notify=1',
        ])
    )
    if ret.status_code != 200:
        write_log_error_and_exit(
            'Error code {}. Quitting.'.format(ret.status_code),
            1,
        )

    # cnames = json.loads(ret.content.('utf-8'))
    cnames_content = ret.content
    cnames = json.loads(cnames_content.decode('utf-8'))
    return cnames

def fetch_ipam_records(session, api):
    
    write_log_info('Fetching IPAM Records.')

    hosts = fetch_ipam_records_host(session, api)
    cnames = fetch_ipam_records_cname(session, api)
    write_log_info('Done fetching IPAM records.')
    return hosts, cnames

def build_nagios_objects(hosts, cnames):
    write_log_info('Building nagios objects.')
    nagios_objects = {}
    # Pull out all of the things from each type of record which are tagged as devicemonitors
    # Nagios really doesn't like doing cnames by hostname, so tag them to use the ip address explicitly with use_ip
    nagios_hosts = {} #final answer
    for host in hosts:
        if 'nagios_notify' in host['extattrs']:
            host['use_ip'] = False
            nagios_hosts[host['name']] = host

    for cname in cnames:
        if 'nagios_notify' in cname['extattrs']:
            cname['use_ip'] = True
            try:
                cname['ipv4addr'] = socket.gethostbyname(cname['dns_canonical'])
                nagios_hosts[cname['name']] = cname
            except socket.gaierror:
                print('Could not resolve cname "{}". Skipping.'.format(cname['dns_canonical']), file=sys.stderr)
                raise
    return nagios_hosts

def get_ipam_session(configuration):
    write_log_info('Getting ipam session.')
    session = requests.Session()
    session.auth = (configuration['username'], configuration['password'])
    try:
        session.get(configuration['api_url'])
    except:
        write_log_error_and_exit(
            'Could not connect to Infoblox WAPI, quitting.',
            1,
        )
        
    return session
    
def dump_nagios_hosts_json(nagios_hosts, filename):
    write_log_info('Writing to %s' % filename)
    hosts_json = json.dumps(nagios_hosts)
    f = open(filename, 'w')
    f.write(hosts_json)
    f.close()
    write_log_info('Done writing.')

## Logging routines

def write_log_start():
    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)
    write_log_info('%s : --BEGINNING--' % sys.argv[0])
    write_log_info('script file: %s' % os.path.realpath(__file__))
    write_log_info('User: %s' % getpass.getuser()) 
    write_log_info('Arguments: %s' % json.dumps(sys.argv))

def write_log_end():
    write_log_info('%s --ENDING--' % sys.argv[0])

def write_log_info(message):
    syslog.syslog(syslog.LOG_INFO, message)

def write_log_error_and_exit(message, exit_value):
    print(message, sys.stderr)
    write_log_info(syslog.LOG_ERR, message)
    sys.exit(exit_value)

## end logging routines

def do_main_processing():

    parser = argparse.ArgumentParser(
        description="Pulls exstible attribute data from IPAM and dumps it in json format.",
    )
     
    parser.add_argument(
        '--config-file',
        '-c',
        type=os.path.expanduser,
        default='~/.config/IAS/ipam_script_user.json',
        help='Path to json config file.',
    )

    parser.add_argument(
        '--output-file',
        type=str,
        nargs='?',
    )
    
    args = parser.parse_args()
    
    configuration_file = args.config_file
    
    configuration = load_ipam_credentials_from_file(configuration_file)
    ipam_session=get_ipam_session(configuration)
    hosts, cnames = fetch_ipam_records(ipam_session, configuration['api_url'])

    nagios_hosts = build_nagios_objects(hosts, cnames)
    if not len(nagios_hosts):
        write_log_error_and_exit(
            'Found zero hosts tagged with the "nagios" extattr. Quitting without overwriting the current record.',
            1
        )

    if not args.output_file:
        write_log_info('Writing to stdout')
        print(json.dumps(nagios_hosts, indent=4, sort_keys=True))
    else :
        dump_nagios_hosts_json(nagios_hosts, args.output_file)

if __name__== '__main__':
    
    write_log_start()
    do_main_processing()
    write_log_end()

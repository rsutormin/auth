#!/usr/bin/env python

# get_nexus_token.py
#
# Installation requirements:
#     1. Globus Online account - register at globusonline.org with
#        a username and password
#     2. httplib2 - run `easy_install httplib2`
# 
# usage: get_nexus_token.py [-h] [-u USERNAME] [-p PASSWORD] [-s URL]
# 
# Get Nexus Token with GO username/password. 
# 
# optional arguments:
#   -h, --help            show this help message and exit
#   -u USERNAME, --username USERNAME
#                         GO Username
#   -p PASSWORD, --password PASSWORD
#                         GO Password
#   -s URL, --url URL     Nexus URL (defaults to production GO instance)
#




import httplib2
import json
import argparse
import getpass
import base64


def get_token(auth_svc, username, password):
    h = httplib2.Http()
    
    auth = base64.encodestring( username + ':' + password )
    headers = { 'Authorization' : 'Basic ' + auth }
    
    h.add_credentials(username, password)
    h.follow_all_redirects = True
    url = auth_svc
    
    resp, content = h.request(url, 'GET', headers=headers)
    status = int(resp['status'])
    if status>=200 and status<=299:
        tok = json.loads(content)
    else: 
        raise Exception(str(resp))
        
    return tok['access_token']

def main():

    parser = argparse.ArgumentParser(description='Get Nexus Token with GO username/password')
    nexus_url = "https://nexus.api.globusonline.org/goauth/token?grant_type=client_credentials"


    parser.add_argument('-u', '--username', help='GO Username')
    parser.add_argument('-p', '--password', help='GO Password')
    parser.add_argument('-s', '--url', help='Nexus URL', default=nexus_url)
    args = parser.parse_args()
    
    url=args.url
    username=args.username
    password=args.password
    if username==None:
        username = raw_input('Username: ')
        password = getpass.getpass(prompt='Password: ') 
    elif password==None:
        password = getpass.getpass(prompt='Password: ') 
            
    tok = get_token(url, username, password)
    print tok
    

if __name__ == '__main__':
    main()
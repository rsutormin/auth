"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from django.conf import settings
from nexus import Client
from pymongo import Connection
import pprint
import json
import os
import base64
import httplib2
import urllib
import time
import random
import string
import operator

# Function to grab a bearer token from Globus Online
# cribbed from Shreyas' cluster services module
#
def get_token(auth_svc, username, password):
    h = httplib2.Http(disable_ssl_certificate_validation=True)
    
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

client = Client(config_file=os.path.join(os.path.dirname(__file__), '../nexus/nexus.yml'))
url = "https://%s/goauth/token?grant_type=client_credentials" % client.config['server']
papatoken = get_token( url, "papa","papapa")
kbusertoken = get_token( url, "kbasetest","@Suite525")
charset = string.ascii_uppercase + string.digits
pp = pprint.PrettyPrinter(indent=4)

class RoleHandlerTest(TestCase):
    """
    Unit Test of REST interface to make sure correct status codes are returned
    Patch the Rabbit connection to fake dispatch
    """

    def setUp(self):
        # TODO: Pull out all the common POST code into setup
        try:
            conn = Connection(settings.MONGODB_CONN)
        except AttributeError as e:
            print "No connection settings specified: %s\n" % e
            conn = Connection()
        except Exception as e:
            print "Generic exception %s: %s\n" % (type(e),e)
            conn = Connection()

        db=conn.authorization
        self.roles = db.roles
        self.testdata = { "role_updater": ["sychan","kbauthorz"],
                          "description": "Steve's test role",
                          "read": [],
                          "create": [],
                          "modify": [],
                          "grant" : [],
                          "role_owner": "kbasetest",
                          "role_id": "unittest_",
                          "impersonate": [],
                          "members": ["sychan","kbasetest","kbauthorz"],
                          "delete": []
                          }

    def testCreate(self):
        h = self.client
        url = "/Roles/"
        authstatus = "/authstatus/"
        testdata = self.testdata
        testdata['role_id'] += "".join(random.sample(charset,10))

        dbobj = self.roles.find( { 'role_id' : testdata['role_id'] } );
        if dbobj.count() != 0:
            self.roles.remove( { 'role_id' : testdata['role_id'] } )

        data = json.dumps(testdata )

        resp = h.post(url, testdata )
        self.assertEqual(resp.status_code, 401, "Should reject create without auth token")

        resp = h.post(url, testdata, HTTP_AUTHORIZATION="OAuth %s" % papatoken )
        self.assertEqual(resp.status_code, 401, "Should reject create without KBase membership")

        resp = h.post(url, testdata, HTTP_AUTHORIZATION="OAuth %s" % kbusertoken )
        self.assertEqual(resp.status_code, 201, "Should accept creation from legit kbase test user")
        # verify that object was inserted into database properly
        dbobj = self.roles.find( { 'role_id' : testdata['role_id'] } );
        self.assertEqual( dbobj.count(), 1, "Should be only a single instance of %s role" % testdata['role_id'])
        testdatadb = dbobj[0];
        del testdatadb['_id']
        # Now we have to convert this to unicode by doing a JSON conversion and then back
        testdata = json.loads(json.dumps( testdata))
        self.assertTrue( testdata == testdatadb,"Data in mongodb should equal source testdata - minus _id field")

        resp = h.post(url, testdata, HTTP_AUTHORIZATION="OAuth %s" % kbusertoken )
        self.assertEqual(resp.status_code, 409, "Should reject creation of duplicate role_id")

        # Remove the database record directly
        self.roles.remove( { 'role_id' : testdata['role_id'] } )

    def testRead(self):
        h = self.client
        url = "/Roles/"

        resp = h.get(url)
        self.assertEqual(resp.status_code, 401, "Should reject queries without auth token")

        resp = h.get(url, {}, HTTP_AUTHORIZATION="OAuth %s" % papatoken)
        self.assertEqual(resp.status_code, 401, "Should reject queries without KBase membership")

        resp = h.get(url, {}, HTTP_AUTHORIZATION="OAuth %s" % kbusertoken)
        self.assertEqual(resp.status_code, 200, "Should accept queries from legit kbase test user")
        respjson = json.loads(resp.content)
        usage = respjson.get('usage')
        self.assertIsNotNone(usage, "Expecting usage message")

        url2 = "%skbase_users" % url
        resp = h.get(url2, {}, HTTP_AUTHORIZATION="OAuth %s" % kbusertoken)
        self.assertEqual(resp.status_code, 200, "Querying for kbase_user role from legit kbase test user")
        respjson = json.loads(resp.content)
        members = respjson.get('members')
        self.assertIsNotNone(members, "Expecting members field")

        # try to query long random role name, expecting no result!
        bogorole = "".join(random.sample(charset,20))
        url2 = "%s%s" % (url,bogorole)
        resp = h.get(url2, {}, HTTP_AUTHORIZATION="OAuth %s" % kbusertoken)
        self.assertEqual(resp.status_code, 200, "Querying for nonexistent role using kbase test user")
        respjson = json.loads(resp.content)
        self.assertIsNone(respjson, "Expecting no response")

        # try a regex filter search for all possible role_ids, but returning only one field
        filter = { "role_id" : { "$regex" : ".*" }}
        filterjs = json.dumps( filter )
        fields = { "role_id" : "1" }
        fieldsjs = json.dumps( fields )
        url2 = "%s?filter=%s&fields=%s" % (url,filterjs,fieldsjs)
        resp = h.get(url2, {}, HTTP_AUTHORIZATION="OAuth %s" % kbusertoken)
        self.assertEqual(resp.status_code, 200, "Querying using regex filter and field selection")
        respjson = json.loads(resp.content)
        self.assertTrue(len(respjson) > 0, "Expecting multiple responses")
        fields = list(set(reduce( operator.add,[x.keys() for x in respjson],[] )))
        self.assertEquals( fields,['role_id'], "Expecting a single field, 'role_id', across all results")

        # double check by pulling all records from mongodb and making sure the role_id values match
        role_ids = list(set(reduce( operator.add,[x.values() for x in respjson],[] )))
        role_ids.sort()
        dbroles = self.roles.find( filter, fields)
        role_idsdb = [x['role_id'] for x in dbroles]
        role_idsdb.sort()
        self.assertEquals( role_ids, role_idsdb, "Should get identical results from pymongo query and REST interface query")

    def testUpdate(self):
        h = self.client
        url = "/Roles/"

        # Push a record into the mongodb directly so that we can modify it
        testdata = self.testdata
        testdata['role_id'] += "".join(random.sample(charset,10))
        try:
            self.roles.insert(testdata)
            testdata2 = testdata
            # try without auth, should fail

            resp = h.put(url, testdata, content-type="application/json")
            self.assertEqual(resp.status_code, 401, "Should reject create without auth token")


            # try an error condition where we leave out the role_id
            del testdata2['role_id']
        #resp = h.post(url, {'data' : data})

        #self.assertEqual(resp.status_code, 200)

        #job_info = json.loads(resp.content)
        #id = job_info['id']
        #url = "/job/%s/" % id

        #state = JobState.completed
        #job_id = "cvr.66"

        #data = json.dumps({'state': state, 'job_id': job_id})

        #resp = h.put(url, {'data' : data})

        #self.assertEqual(resp.status_code, 200)

        #j=Job.objects.get(id=id)
        #self.assertEqual(j.state, state)
        #self.assertEqual(j.job_id, job_id)
        self.assertEqual(0,0)

    def testDelete(self):
        h = self.client
        url = "/Roles/"
        testdata = self.testdata
        testdata['role_id'] += "".join(random.sample(charset,10))

        self.roles.insert( testdata)
        url = "%s%s" % (url, testdata['role_id'])
        resp = h.delete( url)
        self.assertEqual(resp.status_code, 401, "Should reject delete without auth token")

        resp = h.delete( url,{},HTTP_AUTHORIZATION="OAuth %s" % kbusertoken )
        self.assertEqual(resp.status_code, 204, "Should allow delete with kbasetest auth token")

        testdata['role_owner'] = "elmerfudd"
        self.roles.insert( testdata)
        resp = h.delete( url,{},HTTP_AUTHORIZATION="OAuth %s" % kbusertoken )
        self.assertEqual(resp.status_code, 401, "Should reject delete with kbasetest auth token")

        # Remove the database record directly
        self.roles.remove( { 'role_id' : testdata['role_id'] } )




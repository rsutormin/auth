from piston.handler import BaseHandler
from piston.utils import rc
import pprint
import datetime
import json
from pymongo import Connection
from piston.resource import Resource
from django.conf import settings


pp = pprint.PrettyPrinter(indent=4)

# Convert QuerySet into a dictionary keyed on the field named in 2nd parameter
def dictify(objs,key):
    results = {}
    for x in range(len(objs)):
        results[objs[x][key]] = objs[x]
        
    return results

class RoleHandler( BaseHandler):
    allowed_methods = ('GET','POST','PUT','DELETE')
    fields = ('role_id','description','members','read','modify','delete','impersonate','grant','create')
    exclude = ( '_id', )

    # We need to define the appropriate settings and set them here
    try:
        conn = Connection(settings.MONGODB_CONN)
    except AttributeError as e:
        print "No connection settings specified: %s\n" % e
        conn = Connection()
    except Exception as e:
        print "Generic exception %s: %s\n" % (type(e),e)
        conn = Connection()
    db = conn.authorization
    roles = db.roles

    def read(self, request, role_id=None):
        try:
            if role_id == None and 'role_id' in request.GET:
                role_id = request.GET.get('role_id')
            filter = request.GET.get('filter', None)
            fields = request.GET.get('fields', None)
            if role_id == None and filter == None:
                res = { 'id' : 'KBase Authorization',
                        'documentation' : 'https://docs.google.com/document/d/1CTkthDUPwNzMF22maLyNIktI1sHdWPwtd3lJk0aFb20/edit',
                        'resources' : { 'role_id' : 'Unique human readable identifer for role (required)',
                                        'description' : 'Description of the role (required)',
                                        'members' : 'A list of the user_ids who are members of this group',
                                        'read' : 'List of kbase object ids (strings) that this role allows read privs',
                                        'modify' : 'List of kbase object ids (strings) that this role allows modify privs',
                                        'delete' : 'List of kbase object ids (strings) that this role allows delete privs',
                                        'impersonate' : 'List of kbase user_ids (strings) that this role allows impersonate privs',
                                        'grant' : 'List of kbase authz role_ids (strings) that this role allows grant privs',
                                        'create' : 'Boolean value - does this role provide the create privilege'
                                        },
                        'contact' : { 'email' : 'sychan@lbl.gov' }
                        }
            elif role_id != None:
                res = self.roles.find_one( { 'role_id': role_id })
                if res != None:
                    for excl in self.exclude:
                        if excl in res:
                            del res[excl]
            else:
#                print "Filter = %s\n" % pp.pformat(filter)
                filter = json.loads(filter)
                if fields:
                    fields = json.loads(fields)
                    match = self.roles.find(filter, fields)
                else:
                    match = self.roles.find( filter )
                res = [ match[x] for x in range( match.count())]
                for x in res:
                    for excl in self.exclude:
                        if excl in x:
                            del x[excl]
        except Exception as e:
            res = rc.BAD_REQUEST
            res.write('Error: %s' % e )
        return(res)

    def create(self, request):
        r = request.data
#        print pp.pformat( r)
        try:
            if self.roles.find( { 'role_id': r['role_id'] }).count() == 0:
                new = { x : r.get(x, []) for x in ('read','modify','delete','impersonate','grant','create') }
                new['role_id'] = r['role_id']
                new['description'] = r['description']
                self.roles.insert( new)
                res = rc.CREATED
            else:
                res = rc.DUPLICATE_ENTRY
        except KeyError as e:
            res = rc.BAD_REQUEST
            res.write(' required fields: %s' % e )
        except Exception as e:
            res = rc.BAD_REQUEST
            res.write('Error: %s' % e )
        return(res)
    def update(self, request, role_id=None):
        r = request.data
#        print pp.pformat( r)
        try:
            if role_id == None:
                role_id = request.data['role_id']
            old = self.roles.find_one( { 'role_id': role_id })
            if old != None:
                old.update(r)
                self.roles.save( old)
                res = rc.CREATED
            else:
                res = rc.NOT_HERE
        except KeyError as e:
            res = rc.BAD_REQUEST
            res.write(' required fields: %s' % e )
        except Exception as e:
            res = rc.BAD_REQUEST
            res.write('Error: %s' % e )
        return(res)
    def delete(self, request, role_id=None):
        try:
            if role_id == None:
                role_id = request.data['role_id']
            r = self.roles.find_one( { 'role_id': role_id })
            if r != None:
                self.roles.remove( { '_id' : r['_id'] }, safe=True)
                res = rc.DELETED
            else:
                res = rc.NOT_HERE
        except KeyError as e:
            res = rc.BAD_REQUEST
            res.write('role_id must be specified')
        except Exception as e:
            res = rc.BAD_REQUEST
            res.write('Error: %s' % e)
        return(res)



# Handlers for piston API
# sychan 9/6/2012

role_handler = Resource( RoleHandler)

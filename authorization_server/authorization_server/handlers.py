from piston.handler import BaseHandler
from piston.utils import rc
import pprint
import datetime
from pymongo import Connection
from piston.resource import Resource


pp = pprint.PrettyPrinter(indent=4)

# Convert QuerySet into a dictionary keyed on the field named in 2nd parameter
def dictify(objs,key):
    results = {}
    for x in range(len(objs)):
        results[objs[x][key]] = objs[x]
        
    return results

class RoleHandler( BaseHandler):
    allowed_methods = ('GET','POST','PUT','DELETE')
    fields = ('role_id','description','read','modify','delete','impersonate','grant','create')
    exclude = ( '_id' )

    conn = Connection()
    db = conn.authorization
    roles = db.roles

    def read(self, request, role_id=None):
        r = self.roles.find_one( { 'role_id': role_id })
        return(r)
    def create(self, request):
        r = request.data
        print pprint.pformat( r)
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
        print pprint.pformat( r)
        try:
            if role_id == None:
                role_id = request.data['role_id']
            old = self.roles.find_one( { 'role_id': role_id })
            if old != None:
                new = { x : r.get(x, old[x]) for x in ('_id','role_id','description',
                                                       'read','modify','delete',
                                                       'impersonate','grant','create') }
                self.roles.save( new)
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
        return(res)



# Handlers for piston API
# sychan 9/6/2012

role_handler = Resource( RoleHandler)

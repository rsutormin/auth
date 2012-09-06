from piston.handler import BaseHandler
from piston.utils import rc
import pprint
import datetime
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

    def read(self, request):
        return({})
    def create(self, request):
        return({})
    def update(self, request):
        return({})
    def delete(self, request):
        return({})



# Handlers for piston API
# sychan 9/6/2012

role_handler = Resource( RoleHandler)

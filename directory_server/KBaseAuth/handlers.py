from piston.handler import BaseHandler
from piston.utils import rc
from KBaseAuth.models import *
import pprint
import datetime
from django.utils import simplejson
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.decorators import login_required

# Handlers for piston API
# sychan 4/19/2012

pp = pprint.PrettyPrinter(indent=4)

# Convert QuerySet into a dictionary keyed on the field named in 2nd parameter
def dictify(objs,key):
    results = {}
    for x in range(len(objs)):
        results[objs[x][key]] = objs[x]
        
    return results

# Function to return a dictionary of the oauth keys, filtered by
# user_id or by oauth_key
def read_oauthkeys(user_id=None,oauth_key=None):
    base=OAuthKeys.objects
    if (oauth_key):
        objs = base.filter(pk=oauth_key).values()
    elif (user_id):
        objs = base.filter(user_id_id__exact = user_id).values()
    else:
        objs = base.all().values()
    res = dictify(objs,'oauth_key')
    res = strip_id_suffix('user_id',res)
    for key in res.keys():
        tokens = OAuthTokens.objects.filter(oauth_key=res[key]['oauth_key']).values()
        tokens = dictify(tokens,'oauth_token')
        tokens = strip_id_suffix( 'oauth_key',tokens)
        tokens = strip_id_suffix( 'target_user',tokens)
        res[key]['oauth_tokens'] = tokens
    return res

# helper function to strip out _id from nested key names
def strip_id_suffix(dest,dict):
    src = "{0}_id".format(dest)
    for key in dict.keys():
        if (src in dict[key]):
            dict[key][dest] = dict[key][src]
            del dict[key][src]
    return dict

# function to support login function
def login( request ):
    if request.user.is_authenticated():
        print "Authenticated %s, %s" % (request.user.username, request.META['KBASEsessid'])
        response = { 'sessid': request.META['KBASEsessid'], 'user_id': request.user.username}
        return( HttpResponse( simplejson.dumps(response),mimetype='application/json'))
    else:
        return( HttpResponse( "Authentication failed. Requires OAuth authentication for access",status=401))

class ProfileHandler(BaseHandler):
    model = Profile
    fields = ('user_id','enabled','last_login_time','last_login_ip','name','given_name',
              'family_name','middle_name','nickname','profile','picture','website','email',
              'verified','gender','birthday','zoneinfo','locale','phone_number','address',
              'updated_time','oauth_creds')
    def read(self,request,user_id=None):
        if (user_id):
            objs = Profile.objects.filter(pk=user_id).values()
        else:
            objs = Profile.objects.all().values()
        results = dictify(objs,'user_id')
        for user in results.keys():
            results[user]['oauth_creds'] = read_oauthkeys(user)
        return results


class OAuthKeysHandler( BaseHandler):
    model = OAuthKeys
    exclude = ('user_id',)


    def read(self,request,oauth_key=None):
        base=OAuthKeys.objects

        if (oauth_key):
            res = read_oauthkeys(None,oauth_key)
        elif (request.GET.has_key('user_id')):
            res = read_oauthkeys(request.GET['user_id'])
        else:
            res = read_oauthkeys()
        return res

    def create(self,request):
        if request.content_type:
            data = request.data
            
            print "Recieved:\n"
            pp.pprint( data)
            # check for duplicate
            
            try:
                parent = Profile.objects.get(pk=data['user_id'])
            except Profile.DoesNotExist:
                print "No matching parent record"
                return rc.NOT_FOUND
                
            oauthkey = self.model(oauth_key=data['oauth_key'], oauth_secret=data['oauth_secret'],user_id=parent)
            pp.pprint( oauthkey)
            oauthkey.save()
            print "Saved successfully"
            return rc.CREATED
        else:
            super( model, self).create(request)



class OAuthTokensHandler( BaseHandler):
    model = OAuthTokens
    exclude = ('oauth_key',)

    def read(self,request, oauth_token=None):
        base=OAuthTokens.objects

        if (oauth_token):
            print "Searching for {0}\n".format( oauth_token)
            try:
                objs = base.filter(pk=oauth_token)
                objs = objs.values()
            except OAuthTokens.DoesNotExist:
                print "No matching record found for {0}\n".format(oauth_token)
                return rc.NOT_FOUND
        else:
            objs = base.all().values()
        res = dictify(objs,'oauth_token')
        res = strip_id_suffix("oauth_key",res)
        res = strip_id_suffix("target_user",res)
        return res

    def create(self,request):
        if request.content_type:
            data = request.data
            
            print "Recieved:\n"
            pp.pprint( data)
            # check for duplicate
            
            try:
                parent = OAuthKeys.objects.get(pk=data['oauth_key'])
            except OAuthKeys.DoesNotExist:
                print "No matching parent record"
                return rc.NOT_FOUND

            try:
                target = Profile.objects.get(pk=data['target_user'])
            except OAuthKeys.DoesNotExist:
                print "No matching target record"
                return rc.NOT_FOUND
                
            if ( "creation_time" not in data):
                data["creation_time"] = datetime.datetime.now()
            oauthtoken = self.model(oauth_key=parent, oauth_token=data['oauth_token'],access_token=data['access_token'],target_user=target, creation_time=data["creation_time"])
            pp.pprint( oauthtoken)
            oauthtoken.save()
            print "Saved successfully"
            return rc.CREATED
        else:
            super( model, self).create(request)


class GroupHandler( BaseHandler):
    model = Group

class GroupMembersHandler( BaseHandler):
    model = GroupMembers

    def read(self,request, name=None):
        base=GroupMembers.objects

        if (name):
            print "Searching for {0}\n".format( name)
            try:
                groupid = Group.objects.get(pk=name)
                objs = base.filter(name_id=groupid)
                objs = objs.values()
            except Group.DoesNotExist:
                print "No group names {0}\n".format(name)
                return rc.NOT_FOUND
            except GroupMembers.DoesNotExist:
                return []
        else:
            objs = base.all().values()
        res = {}
        for x in range( len(objs)):
            if ( objs[x]['name_id'] not in res ):
                res[objs[x]['name_id']] = []
            res[objs[x]['name_id']].append( objs[x]['user_id_id'])
        return res

    def create(self,request):
        if request.content_type:
            data = request.data
            
            print "Recieved:\n"
            pp.pprint( data)
            # check for duplicate
            
            try:
                group = Group.objects.get(pk=data['name'])
                user = Profile.objects.get(pk=data['user_id'])
            except Group.DoesNotExist:
                print "No matching Group record"
                return rc.NOT_FOUND
            except Profile.DoesNotExist:
                print "No matching user found"
                return rc.NOT_FOUND
                
            groupmember = self.model(name=group,user_id=user)
            pp.pprint( groupmember)
            groupmember.save()
            print "Saved successfully"
            return rc.CREATED
        else:
            super( model, self).create(request)


class RoleHandler( BaseHandler):
    model = Role

class RoleMembersHandler( BaseHandler):
    model = RoleMembers


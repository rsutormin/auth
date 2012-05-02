from piston.handler import BaseHandler
from piston.utils import rc
from KBaseAuth.models import *
import pprint

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
    for key in res.keys():
        tokens = OAuthTokens.objects.filter(oauth_key=res[key]['oauth_key']).values()
        res[key]['oauth_tokens'] = dictify(tokens,'oauth_token')
        # Replace key user_id_id with user_id
        res[key]['user_id'] = res[key]['user_id_id']
        del res[key]['user_id_id']
    return res

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
            objs = base.get(pk=oauth_token).values()
        else:
            objs = base.all().values()
        res = dictify(objs,'oauth_token')
        for key in res.keys():
            # Replace key oauth_key_id with oauth_key
            res[key]['oauth_key'] = res[key]['oauth_key_id']
            del res[key]['oauth_key_id']
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
                
            oauthtoken = self.model(oauth_key=parent, oauth_token=data['oauth_token'],access_token=data['access_token'])
            pp.pprint( oauthtoken)
            oauthtoken.save()
            print "Saved successfully"
            return rc.CREATED
        else:
            super( model, self).create(request)


class GroupHandler( BaseHandler):
    model = Group

class RoleHandler( BaseHandler):
    model = Role

class RoleMembersHandler( BaseHandler):
    model = RoleMembers


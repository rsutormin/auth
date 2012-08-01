import logging
import oauth2
import httplib2
import json

from django.contrib.auth.models import AnonymousUser,User
from django.contrib.auth import login,authenticate
from django.contrib.auth.middleware import AuthenticationMiddleware

"""
This is the 2-legged OAuth authentication code from tastypie
converted into a django authentication middleware and backend.
It has an analog to RemoteUserMiddleware so that we can get access to the
request object - the middleware code is mostly copied from
gaeoauth middle.py

This is a simple 2-legged OAuth authentication model for tastypie.

Copied nearly verbatim from gregbayer's piston example 
 - https://github.com/gregbayer/django-piston-two-legged-oauth

Dependencies: 
 - python-oauth2: https://github.com/simplegeo/python-oauth2
Adapted from example:  
 - http://philipsoutham.com/post/2172924723/two-legged-oauth-in-python
"""

class TwoLeggedOAuthMiddleware(AuthenticationMiddleware):

    """
    Two Legged OAuth authenticator. 
    
    This Authentication method checks for a provided HTTP_AUTHORIZATION
    and looks up to see if this is a valid OAuth Consumer
    """

    # Authentication server
    authsvc = 'http://140.221.92.45'

    def __init__(self, realm='API'):
        self.realm = realm
        self.user = None
        self.http = httplib2.Http()


    def process_request(self, request):
        """
        Verify 2-legged oauth request. Parameters accepted as
        values in "Authorization" header, or as a GET request
        or in a POST body.
        """
        # AuthenticationMiddleware is required so that request.user exists.
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The Django remote user auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the RemoteUserMiddleware class.")
        oauth_server, oauth_request = initialize_oauth_server_request(request)
        try:
            key = request.GET.get('oauth_consumer_key')
            if not key:
                key = request.POST.get('oauth_consumer_key')
            if not key:
                auth_header_value = request.META.get('HTTP_AUTHORIZATION')
                key = get_oauth_consumer_key_from_header(auth_header_value)
            if not key:
                return None
            consumer = self.get_consumer(key)
            # See if the consumer key is already associated with any currently logged
            # in user, if so just pass over the rest
            if (request.user.is_authenticated()):
                if request.user.username == consumer['user_id']:
                    print "Request username matches consumer user_id"
                    return
            # Raises exception if it doesn't pass 
            oauth_server.verify_request(oauth_request, oauth2.Consumer(consumer['oauth_key'],consumer['oauth_secret']), None)
            user = authenticate(remote_user=consumer['user_id'])
            if user:
                request.user = user
                login(request,user)
            else:
                logging.error( "Failed to return user from call to authenticate() with username " + consumer['user_id'])
        except oauth2.Error, e:
            logging.exception("Error in TwoLeggedOAuthMiddleware.")
            request.user = AnonymousUser()
        except KeyError, e:
            logging.exception("Error in TwoLeggedOAuthMiddleware.")
            request.user = AnonymousUser()
        except Exception, e:
            logging.exception("Error in TwoLeggedOAuthMiddleware.")


    def get_consumer(self,key):
        keyurl = self.__class__.authsvc + "/oauthkeys/" + key
        try:
            res,body = self.http.request(keyurl)
            if (200 <= int(res.status)) and ( int(res.status) < 300):
                consumer = json.loads( body)
                consumer = consumer[key]
                return consumer
            raise Exception("HTTP", res)
        except:
            return None

def initialize_oauth_server_request(request):
    """
    OAuth initialization.
    """
    
    # Since 'Authorization' header comes through as 'HTTP_AUTHORIZATION', convert it back
    auth_header = {}
    if 'HTTP_AUTHORIZATION' in request.META:
        auth_header = {'Authorization':request.META.get('HTTP_AUTHORIZATION')}
    
    absolute_uri = request.build_absolute_uri()
    url = absolute_uri
    if absolute_uri.find('?') != -1:
        url = absolute_uri[:absolute_uri.find('?')]
        
    oauth_request = oauth2.Request.from_request(
            request.method, url, headers=auth_header, 
            parameters=dict(request.REQUEST.items()))
        
    if oauth_request:
        oauth_server = oauth2.Server(signature_methods={
            # Supported signature methods
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

    else:
        oauth_server = None
    return oauth_server, oauth_request


def get_oauth_consumer_key_from_header(auth_header_value):
    key = None
    
    # Process Auth Header
    # Check that the authorization header is OAuth.
    if not auth_header_value:
        return None
    if auth_header_value[:6] == 'OAuth ':
        auth_header = auth_header_value[6:]
        try:
            # Get the parameters from the header.
            header_params = oauth2.Request._split_header(auth_header)
            if 'oauth_consumer_key' in header_params:
                key = header_params['oauth_consumer_key']
        except:
            raise Exception('Unable to parse OAuth parameters from '
                'Authorization header.')
    return key




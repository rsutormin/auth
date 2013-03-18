"""
Kbase wrappers around Globus Online Nexus client libraries. We wrap the Nexus
libraries to provide a similar API between the Perl Bio::KBase::Auth* libraries
and the python version

In this module, we follow standard Python idioms of raising exceptions for
various failure states ( Perl modules returned error states in error_msg field)

"""

from biokbase.nexus.client import NexusClient
from ConfigParser import ConfigParser
import os
from urlparse import urlparse

kb_config = os.environ.get('KB_DEPLOYMENT_CONFIG',os.environ['HOME']+"/.kbase_config")

def LoadConfig():
    """
    Method to load configuration from INI style files from the file in kb_config
    """
    pass

def SetConfigs():
    """
    Method used to set configuration directives in INI file kb_config
    """
    pass

class AuthCredentialsNeeded( Exception ):
    """
    Simple wrapper around Exception class that flags the fact that we don't have
    enough credentials to authenticate, which is distinct from having bad or bogus
    credentials
    """
    pass

class AuthFail( Exception ):
    """
    Simple wrapper around Exception class that flags our credentials are bad or bogus
    """
    pass

class Token:
    """
    Class that handles token requests and validation. This is basically a wrapper
    around the nexus.client.NexusClient class from GlobusOnline that provides a
    similar API to the perl Bio::KBase::AuthToken module. For KBase purposes
    we have modified the base Globus Online classes to support ssh agent based
    authentication as well.

    In memory caching is provided by the underlying nexus.client implementation.

    Class Attributes:
    trust_token_signers
    attrs
    authdata
    config
    tokenend
    AuthSvcHost
    RoleSvcURL
    nexusconfig

    Instance Attributes:
    user_id 
    password 
    token 
    keyfile 
    client_secret 
    keyfile_passphrase 
    sshagent_keyname 
    """

    trust_token_signers = [ 'https://nexus.api.globusonline.org/goauth/keys' ]
    attrs = [ 'user_id', 'auth_token','client_secret', 'keyfile',
              'keyfile_passphrase','password','sshagent_keys',
              'sshagent_keyname']
    authdata = dict()
    if os.path.exists( kb_config):
        try:
            config = ConfigParser()
            config.read(file)
            # strip down whatever we read to only what is legit
            authdata = { x : config.get('authentication',x) if config.has_option('authentication',x) else None for x in
                         attrs }
        except Exception, e:
            print "Error while reading INI file %s: %s" % (file, e)
    tokenenv = authdata.get( 'tokenvar', 'KB_AUTH_TOKEN')
    # Yes, some variables are camel cased and others are all lower. Trying to maintain
    # the attributes names from the perl version which was a mishmash too. regret.
    AuthSvcHost = authdata.get( 'servicehost', "https://nexus.api.globusonline.org/")
    # Copied from perl libs for reference, not used here
    #ProfilePath = authdata.get( 'authpath', "/goauth/token")
    RoleSvcURL = authdata.get( 'rolesvcurl', "https://kbase.us/services/authorization/Roles")
    nexusconfig = { 'cache' : { 'class': 'nexus.token_utils.InMemoryCache',
                                'args': [],
                                },
                    'server' : urlparse(AuthSvcHost).netloc,
                    'verify_ssl' : False,
                    'client' : None,
                    'client_secret' : None}

    def __init__(self, user_id = None, password = None, token = None,
                 keyfile = None, client_secret = None, keyfile_passphrase = None,
                 sshagent_keyname = None):
        """
        Constructor for Token class will accept these optional parameters attributes in
        order to initialize the object:

        user_id, password, token, keyfile, client_secret, keyfile_passphrase, sshagent_keyname

        If user_id is provided among the initializers, the get() method will be called at the
        end of initialization to attempt to fetch a token from the service defined in
        AuthSvcHost. If there are not enough credentials to authenticate, we ignore the
        exception. However if there are enough credentials and they fail to authenticate,
        the exception will be reraised.
        """
        self.token = None
        self.user_id = user_id if user_id else None
        self.password = password if password else None
        self.keyfile = keyfile if keyfile else None
        self.client_secret = client_secret if client_secret else None
        self.keyfile_passphrase = keyfile_passphrase if keyfile_passphrase else None
        self.sshagent_keyname = sshagent_keyname if sshagent_keyname else None
        self.nclient = NexusClient(self.nexusconfig)
        self.sshagent_keys = self.nclient.agent_keys

        # if we have a user_id defined, try to get a token with whatever else was given
        # if it fails due to not enough creds, ignore
        if (self.user_id):
            try:
                self.get()
            except AuthCredentialsNeeded:
                pass
            except Exception, e:
                raise e

    def validate( self, token = None):
        """
        Method that validates the contents of self.token against the authentication service backend
        This method caches results, so an initial validation will be high latency due to the
        network round trips, but subsequent validations will return very quickly

        A successfully validated token will return a tuple of (user_id,authentication source)

        Invalid tokens will generate a ValueError exception
        """
        if token is not None:
            return self.nclient.validate_token( token)
        else:
            return self.nclient.validate_token( self.token)

    def get(self, **kwargs):
        """
        Use either explicit parameters or the current instance vars to authenticate and retrieve a
        token from GlobusOnline (or whoever else is defined in the AuthSvcHost class attribute).

        The following parameters are optional, and will be assigned to the instance vars before
        attempting to fetch a token:
        keyfile, keyfile_passphrase, user_id, password, client_secret, sshagent_keyname

        A user_id and any of the following will be enough to attempt authentication:
        keyfile, keyfile_passphrase, password, sshagent_keyname

        If there are not enough credentials, then an AuthCredentialsNeeded exception will be raised
        If the underlying Globus libraries fail to authenticate, the exception will be passed up

        Success returns self, but with the token attribute containing a good token

        Note: authentication with an explicit RSA client_secret is not currently supported
        """
        # attributes that we would allow to be passed in via kwargs
        attrs = [ 'keyfile','keyfile_passphrase','user_id','password','token','client_secret','sshagent_keyname']
        for attr in attrs:
            if attr in kwargs:
                setattr( self, attr, kwargs[attr])
        # override the user_key_file default in the nclient object
        self.nclient.user_key_file = self.keyfile
        if not (self.user_id and ( self.password or self.sshagent_keyname or self.keyfile)):
            raise AuthCredentialsNeeded( "Need either (user_id, client_secret || password || sshagent_keyname)  to be defined.")
        if self.keyfile:
            self.nclient.user_key_file = self.keyfile
        if (self.user_id and self.keyfile):
            res = self.nclient.request_client_credential( self.user_id, kwargs.get("keyfile_passphrase",None))
        elif (self.user_id and self.password):
            res = self.nclient.request_client_credential( self.user_id, self.password)
        elif (self.user_id and self.sshagent_keyname):
            res = self.nclient.request_client_credential_sshagent( self.user_id, self.sshagent_keyname)
        else:
            raise AuthCredentialsNeeded("Authentication with explicit client_secret not supported - please put key in file or sshagent")
        if 'access_token' in res:
            self.token = res['access_token']
        else:
            raise AuthFail()
        return self

    def get_sessDB_token():
        pass

class User:
    def __init__(self):
        pass




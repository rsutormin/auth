from piston.handler import BaseHandler
from KBaseAuth.models import *

class ProfileHandler(BaseHandler):
    model = Profile

class OAuthKeysHandler( BaseHandler):
    model = OAuthKeys

class OAuthTokensHandler( BaseHandler):
    model = OAuthTokens

class GroupHandler( BaseHandler):
    model = Group

class RoleHandler( BaseHandler):
    model = Role

class RoleMembersHandler( BaseHandler):
    model = RoleMembers


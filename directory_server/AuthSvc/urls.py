from django.conf.urls.defaults import patterns, include, url
from piston.resource import Resource
from KBaseAuth.handlers import *
from django.contrib.auth.decorators import login_required

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

# RESTful handlers
profile_rez = Resource( ProfileHandler)
oauthkeys_rez = Resource( OAuthKeysHandler)
oauthtokens_rez = Resource( OAuthTokensHandler)
group_rez = Resource( GroupHandler)
groupmembers_rez = Resource( GroupMembersHandler)
role_rez = Resource( RoleHandler)
rolemembers_rez = Resource( RoleMembersHandler)

urlpatterns = patterns('',

    url(r'^/*profiles/(?P<user_id>\w+)$', login_required(profile_rez)),
    url(r'^/*profiles/?$', login_required(profile_rez)),
    url(r'^/*oauthkeys/(?P<oauth_key>\w+)$', login_required(oauthkeys_rez)),
    url(r'^/*oauthkeys/?$', login_required(oauthkeys_rez)),
    url(r'^/*oauthtokens/?$', login_required(oauthtokens_rez)),
    url(r'^/*oauthtokens/(?P<oauth_token>\w+)$', login_required(oauthtokens_rez)),
    url(r'^/*group/(?P<name>[-\w]+)$', login_required(group_rez)),
    url(r'^/*group$', login_required(group_rez)),
    url(r'^/*groupmembers/(?P<name>[\w-]+)$', login_required(groupmembers_rez)),
    url(r'^/*groupmembers/?$', login_required(groupmembers_rez)),
    url(r'^/*role/(?P<name>[-\w]+)$', login_required(role_rez)),
    url(r'^/*role$', login_required(role_rez)),
    url(r'^/*rolemembers/(?P<name>\w+)$', login_required(rolemembers_rez)),
    url(r'^/*rolemembers$', login_required(rolemembers_rez)),
    url(r'^/*login/?$', login),
    url(r'^/*accounts/login/?$', login),

    # Uncomment the admin/doc line below to enable admin documentation:
    url(r'^/*admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^/*admin/', include(admin.site.urls)),
)

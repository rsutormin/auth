from KBaseAuth.models import *
from django.contrib import admin

class OAuthKeysInline( admin.TabularInline):
    model = OAuthKeys
    extra = 1

class ProfileAdmin( admin.ModelAdmin):
    inlines = [OAuthKeysInline]
    fieldsets = [
        ( None,                 {'fields': [('user_id','enabled'),'name',('email','verified')]}),
        ( 'Activity',           {'fields': [('last_login_time','last_login_ip')]}),
        ( 'Misc Profile',       {'fields': ['address','phone_number',
                                            ('given_name','middle_name','family_name','nickname'),
                                            'profile','picture','website','gender','birthday','zoneinfo',
                                            'locale','updated_time'],
                                 'classes': ['collapse']})]

class OAuthTokensInline( admin.TabularInline):
    model = OAuthTokens
    extra = 1
    fields = ['oauth_token','access_token']

class OAuthKeysAdmin( admin.ModelAdmin):
    inlines = [OAuthTokensInline]
    fieldsets = [
        (None,                  {'fields': ['user_id',('oauth_key','oauth_secret')]})]

admin.site.register( Profile, ProfileAdmin)
admin.site.register( OAuthKeys, OAuthKeysAdmin)

admin.site.register(Group)
admin.site.register(Role)

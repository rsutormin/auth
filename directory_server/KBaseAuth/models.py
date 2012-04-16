from django.db import models

# Create your models here.

# Main user profie. Includes lots of optional fields to support OAuth
# profile spec
class Profile(models.Model):
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
    )

    user_id = models.CharField(max_length=64, primary_key=True)
    enabled = models.BooleanField(default=False)
    last_login_time = models.DateTimeField(blank=True,null=True)
    last_login_ip = models.IPAddressField(blank=True,null=True)
    name = models.CharField(max_length=100)
    given_name = models.CharField(max_length=32,blank=True)
    family_name = models.CharField(max_length=36,blank=True)
    middle_name = models.CharField(max_length=32,blank=True)
    nickname = models.CharField(max_length=32,blank=True)
    profile = models.URLField(max_length=200,blank=True)
    picture = models.URLField(max_length=200,blank=True)
    website = models.URLField(max_length=200,blank=True)
    email = models.EmailField()
    verified = models.BooleanField(blank=True,default=False)
    gender = models.CharField(max_length=1,blank=True,choices=GENDER_CHOICES)
    birthday = models.DateField(blank=True,null=True)
    zoneinfo = models.CharField(max_length=36,blank=True)
    locale = models.CharField(max_length=16,blank=True)
    phone_number = models.CharField(max_length=20,blank=True)
    address = models.CharField(max_length=200,blank=True)
    updated_time = models.DateTimeField(blank=True,null=True)

    def __unicode__(self):
        return '{0} ({1})'.format(self.user_id,self.email)

# Stores OAuth keypairs. There is a many to one mapping between this
# table the profile table. Clients are identified by the oauth_key
# so it needs to be unique across all users
# For 2 legged oauth this is all that is necessary
class OAuthKeys(models.Model):
    user_id = models.ForeignKey(Profile)
    oauth_key = models.CharField(max_length=74, unique=True)
    oauth_secret = models.CharField(max_length=200)
    def __unicode__(self):
        return '{0} {1}'.format(self.user_id,self.oauth_key)

# Stores the access tokens used for 3 legged OAuth
class OAuthTokens(models.Model):
    user_id = models.ForeignKey(Profile)
    oauth_key = models.ForeignKey(OAuthKeys)
    oauth_token = models.CharField(max_length=200,unique=True)
    access_token = models.BooleanField(default=False)
    creation_time = models.DateTimeField(auto_now_add=True)

# Group membership. No actual ACL's are stored here, just
# membership
class Group(models.Model):
    name = models.CharField(max_length=64,unique=True)

# Group members
class GroupMembers(models.Model):
    name = models.ForeignKey( Group)
    user_id = models.ForeignKey( Profile)

# Role membership. No actual ACL's here, just membership
class Role(models.Model):
    name = models.CharField(max_length=64,unique=True)

# Members of a role
class RoleMembers(models.Model):
    name = models.ForeignKey( Role)
    user_id = models.ForeignKey( Profile)

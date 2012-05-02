
   This directory contains code for the directory server used to back the KBase AuthDirectory class in ../libs/

   KBaseAuth is a django app that implements the directory/profile back end.

   There handlers defined for these objects:

   /profiles(/userid) - returns a json string containing the profile information for the given user, or for all users
   /oauthkeys(/oauth_key(?user_id=USER) - returns the oauth key information for the given consumer_key, or all the consumer
            keys for the user user
   /oauthtokens(/oauth_token) - returns the token information for the given token string
   /group(/group_name) - returns the groups that are defined
   /groupmembers(/group_name) - returns the members of the given group

   Here are sample responses for each of the handlers

GET /profiles
  returns
{
    "sychan": {
        "website": "", 
        "locale": "", 
        "oauth_creds": {
            "key3": {
                "oauth_secret": "secret3", 
                "oauth_key": "key3", 
                "oauth_tokens": {}, 
                "user_id": "sychan"
            }, 
            "key2": {
                "oauth_secret": "secret2", 
                "oauth_key": "key2", 
                "oauth_tokens": {
                    "token2": {
                        "access_token": false, 
                        "target_user": "jqpublic", 
                        "creation_time": "2012-05-02T14:03:22.502", 
                        "oauth_key": "key2", 
                        "oauth_token": "token2"
                    }
                }, 
                "user_id": "sychan"
            }, 
            "key1": {
                "oauth_secret": "secret1", 
                "oauth_key": "key1", 
                "oauth_tokens": {
                    "token1": {
                        "access_token": false, 
                        "target_user": "sychan", 
                        "creation_time": "2012-04-26T14:15:01.700", 
                        "oauth_key": "key1", 
                        "oauth_token": "token1"
                    }
                }, 
                "user_id": "sychan"
            }, 
            "key5": {
                "oauth_secret": "secret5", 
                "oauth_key": "key5", 
                "oauth_tokens": {}, 
                "user_id": "sychan"
            }, 
            "key4": {
                "oauth_secret": "secret4", 
                "oauth_key": "key4", 
                "oauth_tokens": {}, 
                "user_id": "sychan"
            }
        }, 
        "last_login_ip": "127.0.0.1", 
        "user_id": "sychan", 
        "last_login_time": "2012-04-26T14:11:30", 
        "zoneinfo": "", 
        "middle_name": "", 
        "given_name": "", 
        "email": "sychan@lbl.gov", 
        "phone_number": "", 
        "picture": "", 
        "birthday": null, 
        "profile": "", 
        "address": "", 
        "verified": true, 
        "nickname": "", 
        "family_name": "", 
        "name": "Steve Chan", 
        "gender": "", 
        "enabled": true, 
        "updated_time": null
    },
    "jqpublic": { [snip]
    }, 
    "kkeller": {  [snip]
    }, 
    "mike": { [snip]
    } 
}

   To create a user record POST the following:
POST /profiles
{
        "website": "", 
        "locale": "", 
        "last_login_ip": "127.0.0.1", 
        "user_id": "USER_ID", 
        "last_login_time": "2012-04-26T14:11:30", 
        "zoneinfo": "", 
        "middle_name": "", 
        "given_name": "", 
        "email": "EMAIL ADDR", 
        "phone_number": "", 
        "picture": "", 
        "birthday": null, 
        "profile": "", 
        "address": "", 
        "verified": true, 
        "nickname": "", 
        "family_name": "", 
        "name": "FULL NAME", 
        "gender": "", 
        "enabled": true, 
        "updated_time": null
    }

GET /oauthkeys
{
	"key3": {...},-
	"key2": {
		"oauth_secret": "secret2",
		"oauth_key": "key2",
		"oauth_tokens": {
			"token2": {
				  "access_token": false,
				  "target_user": "jqpublic",
				  "creation_time": "2012-05-02T14:03:22.502",
				  "oauth_key": "key2",
				  "oauth_token": "token2"
				  }
			},
		"user_id": "sychan"
		},
	"key1": {...},
	"key6": {...},
	"key5": {...},
	"key4": {...}
}

To create a new oauthkey POST the following
{
        "oauth_secret": "secret3", 
        "oauth_key": "key3", 
        "user_id": "sychan"
}

GET /oauthtokens

   GET /groupmembers
{
    "kbase-users": [
        "jqpublic"
    ], 
    "kbase-staff": [
        "sychan", 
        "jqpublic"
    ]
}

   For creating new group members use a POST with a JSON string of { "name": GROUPNAME, "user_id":USER_ID }




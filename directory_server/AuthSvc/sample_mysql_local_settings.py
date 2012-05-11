DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'kbauthtest',              # Or path to database file if using sqlite3.
        'USER': 'kbauthtestuser',          # Not used with sqlite3.
        'PASSWORD': 'kbauthpassword',      # Not used with sqlite3.
        'HOST': 'db1.chicago.kbase.us',    # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}

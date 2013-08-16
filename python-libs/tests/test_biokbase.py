"""
   Tests for the biokbase.auth.* modules

"""

import unittest
import biokbase.auth
import os
import subprocess
import re
import signal

class test_AuthToken( unittest.TestCase):

    accounts = { 'papa' : 'papapa',
                 'kbasetest' : '@Suite525'}

    filesRestore = dict()
    pid = str(os.getpid())
    # Setup the filenames for the ssh-keys. The first is unencrypted, the second is
    # encrypted. Order matters because the testRSALogin method will use them
    filesDelete = [ ".".join(['/tmp/id_rsa',pid]), ".".join(['/tmp/id_rsa_encrypted',pid]) ]

    @classmethod
    def rename(cls,filename):
        if os.path.exists( filename):
            new = ".".join( [filename,cls.pid])
            os.rename( filename, new)
            cls.filesRestore[ new ] = filename

    @classmethod
    def restore(cls):
        for filename in cls.filesRestore.keys():
            if os.path.exists( filename):
                os.rename( filename, cls.filesRestore[filename])

    @classmethod
    def setUpClass(cls):
        # Make sure we have an ssh-agent and ssh-add executable in the path
        # before continuing
        try:
            sshagentPath = subprocess.check_output(["which","ssh-agent"])
            sshaddPath = subprocess.check_output(["which","ssh-add"])
        except Exception, e:
            raise Exception( "Error looking for ssh-agent and/or ssh-add in current $PATH. Please correct and re-run: %s" % e)
        # Clear up any custom/personal configs before starting tests
        if 'TokenEnv' in os.environ:
            del os.environ['TokenEnv']
        for file in [ biokbase.auth.kb_config ]:
            cls.rename( file)
        biokbase.auth.authdata = dict()
        biokbase.auth.LoadConfig()
        # Create RSA keys file to use for testing, this first
        # is unencrypted, the second has the passphrase
        # "SecretSquirrel"
        rsakey1 = """-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC1QVwNCLinZJfKBfFaQm2nZQM0JvwVhV5fwjiLkUPF51I2HfEX
h988fOc2aOWuhPxUYOnE6I5xqMeWVh5T/77tOLs14X7O6kkmQZhsURKeIv9TVwNM
KoHyBRoE70p+K1qAA7szhz4DE+L0OuNa7H6oFVmpoOPq5GBwFqnFZZwqTwIBIwKB
gENSyms9wO23phfWUlS5lnFgCIEVy1hzXZFII6GNuhZOmuDmjL+Y3eNEVeECY/Bd
R8eRteoNPDjYSiHlePqg0eJ1CclHYOTR/ngBmqNxh5fSgscSPHIuoKlEVRrQE2BY
xM+BxMV4Kz7cZ3YKHrgMvHeNBL1eAhlO9iH4ur6i/UlDAkEA2loWVhabzQ2m3DYN
6m7W5NLuBIqRyvNh/zX8gETqwDWynLri4AAcBcerDPghnXkJDqlM7AgG8W1z05A1
VLhjpQJBANSB2kFjVOfdKJwkfvnn82nf/peHODDKUiaIwD7RaKOJFOI9ULJ6s/fJ
qOtJv/Gnv563Sy3p7pSDtH4PGKjXY+MCQBK3Q748c8EebWNVFyK5Cxrtgh2lejX3
mq95p+28w6oTOzIBY+dQd241r5Nlub0KX9yvbP5J1LWbqteepXxKUa8CQHNcbyrP
hdz0ZoCmGQtSB8vCvWgzdkZfM+kIaFydkJNKamwv6fp9H95I5qudEG09zmwaXAL7
VaEUTAnq8CEkeA0CQQCC4JLKFblHiZdEFzn6jkYe4s9Nf6SX7A+Vn4hq1o9yVMzf
+fEfmgafrDgETuDY9fbv8DwfGtIgaWsbXbvXKdFd
-----END RSA PRIVATE KEY-----
"""
        rsakey2="""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,5B6F21C08A0E8EF9

Z7mH/uXzbnBdZNIk7QLlsgmzkQh8ehQ1R3fSf/d0aivsKrd+jI88hF4xAzMmgZBP
zD3pbOQpL5qhLhOCMqotPCnorUiZtOOMD0NHYXlfqFw0zYWXsFEDAdj1uYN6Phiz
yaimSEJdOe4fMbV2X4u/Kv04ST+4n1aksaxpOOz2rYmFmeFN1oPDp9nWaeLugNwH
RsSm6SzV8Zdd12sd4MAoJRfXjui/ava4Nyj16D4sXq6+/0TdPWy4Wo8GVqvGj9Hi
2oYlrxE8nerFHMu/OHCFpGnOr7wQXkd+UGwA/AFnXEdW3fSnUvYY2PTCUv360WOY
4b+G7vXsGyf25NVcNn1++MaN9dfwK+UkXW3O7davcYh7Gk3B2k5rsGLTDWlgVJSI
pyi2ioHhGhwKCzsKuZYOygN+j2Uf3UlsyA5l5tlTNSErgK+pMyv8Xtpd1C+YuITA
Lp9H7Tz9T0wexdJzlU6WoKAwibW0mZEfJrUqZmMtZoij7gFraKGyHChIG19bORpn
LbjniHG4xtT2LI6fjjdZ4s75mdh+pR00GSrarVpBrmh1i8ixjpseNZBvfu91XnrB
8nadlrRhy1hjY0SLGa6+2zN/78qYdMzrttIEzhJBMICYabb8E4a92or+Y4Ory6wK
YMFWupgmFi0HhpWjzQsentagCbiZU9E3pAokjti67Kwjxl/Xk7DDj0prJNNnt9mA
c9sQJRXETpSW17wDjKWO8SqzZ9EaI9l0Td5N7vOhOGJwUzWcPET3DYWg0XKd+SW/
Q8aeVU7+7MjBYC2IQbg8MO1Yf2EDWrKgHhUPg8lvrA0=
-----END RSA PRIVATE KEY-----
"""
        fn = cls.filesDelete[0]
        rsafile = open(fn,"w")
        rsafile.write(rsakey1)
        rsafile.close()
        os.chmod(fn,0600)
        fn = cls.filesDelete[1]
        rsafile = open(fn,"w")
        rsafile.write(rsakey2)
        rsafile.close()
        os.chmod(fn,0600)

    @classmethod
    def tearDownClass(cls):
        # restore old config files
        cls.restore()
        for fn in cls.filesDelete:
            os.remove(fn)

    def testNull(self):
        self.assertTrue( True, "Dummy test method")

    def testUserPassword(self):
        """
        Test various aspects of username and password logins
        """
        self.assertIsInstance( biokbase.auth.Token(user_id='papa',password=self.accounts['papa']), biokbase.auth.Token)
        t=biokbase.auth.Token(user_id='papa',password=self.accounts['papa'])
        self.assertEqual( t.user_id, "papa", msg="User_id should equal 'papa' for new object")
        self.assertTrue( t.validate(), msg="Should validate for non-kbase user 'papa' token")
        self.assertTrue( t.validate(t.token), msg="Should validate for non-kbase user 'papa' token using explicit validation")
        self.assertTrue( biokbase.auth.Token(user_id='kbasetest',password=self.accounts['kbasetest']).validate(),
                         msg="Should be able to validate token for legit kbasetest user login")
        with self.assertRaises( biokbase.auth.AuthFail,msg="Bad password should not validate"):
            biokbase.auth.Token(user_id='papa',password='poopa').validate(), 
        with self.assertRaises( AttributeError,msg="Empty password should not validate"):
            biokbase.auth.Token(user_id='papa_blah',password='').validate(), 
        with self.assertRaises( AttributeError,msg="Empty user and password should not validate"):
            biokbase.auth.Token(user_id=None,password=None).validate(), 
        badtoken = "un=papa|clientid=papa|expiry=1376607863|SigningSubject=https://graph.not.api.test.globuscs.info/goauth/keys/861eb8e0-e634-11e1-ac2c-1231381a5994|sig=321ca03d17d984b70822e7414f20a73709f87ba4ed427ad7f41671dc58eae15911322a71787bdaece3885187da1158daf37f21eadd10ea2e75274ca0d8e3fc1f70ca7588078c2a4a96d1340f5ac26ccea89b406399486ba592be9f1d8ffe6273b7acdba8a0edf4154cb3da6caa6522f363d2f6f4d04e080d682e15b35f0bbc36"
        t=biokbase.auth.Token(user_id='papa',token=badtoken)
        self.assertEqual( t.user_id, "papa", msg="User_id should equal 'papa' for new badtoken object")
        with self.assertRaises( Exception, msg="Should not validate for non-kbase user 'papa' token"):
            t.validate()
        self.assertTrue( t.get( user_id = 'papa', password = self.accounts['papa']).validate(), msg="Should validate with parameters passed into get()")
        os.environ[biokbase.auth.tokenenv] = t.token
        t2=biokbase.auth.Token()
        self.assertTrue( t2.validate(), msg="Should validate with parameters passed into get()")

    def testInitFiles(self):
        """
        Test the INI file related functions
        """
        biokbase.auth.SetConfigs( { 'user_id' : 'kbasetest',
                                    'password' : self.accounts['kbasetest']})
        biokbase.auth.LoadConfig()
        self.assertTrue( (biokbase.auth.authdata['user_id'] == 'kbasetest'), msg="User_id should be set to kbasetest in .kbase_config")
        self.assertTrue( (biokbase.auth.authdata['password'] == self.accounts['kbasetest']), msg="Password should be set in .kbase_config")
        t=biokbase.auth.Token()
        self.assertTrue( t.token, msg="Should be able to acquire token using .kbase_config")
        biokbase.auth.SetConfigs( { 'user_id' : None, 'password' : None})
        biokbase.auth.LoadConfig()
        
        
    def testRSALogin(self):
        """
        Test logins using RSA keys, both the ~/.ssh/id_rsa variety and the ssh-agent based
        Spins up an ssh-agent instance and loads it with key from self.filesDelete[0]
        """
        t = biokbase.auth.Token( user_id="kbasetest", keyfile=self.filesDelete[0])
        self.assertIsInstance(t,biokbase.auth.Token,msg="Should be able to initialize token with user_id and keyfile")
        self.assertTrue(t.token,msg="Should have a token from keyfile initialization")
        self.assertTrue(t.validate(),msg="Should be able to validate token from keyfile")
        with self.assertRaises( biokbase.auth.AuthCredentialsNeeded, msg="keyfile without user_id should raise exception"):
            biokbase.auth.Token(keyfile=self.filesDelete[0]).get()
        with self.assertRaises( ValueError, msg="user_id with bogus keyfile should raise exception"):
            biokbase.auth.Token(user_id="kbasetest", keyfile="/dev/null")
        with self.assertRaises( ValueError, msg="encrypted keyfile with no passphrase should raise error"):
            t = biokbase.auth.Token(user_id="kbasetest", keyfile=self.filesDelete[1])
        t = biokbase.auth.Token(user_id="kbasetest", keyfile=self.filesDelete[1],keyfile_passphrase="SecretSquirrel")
        self.assertIsInstance(t,biokbase.auth.Token,msg="Should be able to initialize token with user_id, keyfile, keyfile_passphrase")
        self.assertTrue(t.token,msg="Should have a token from keyfile initialization")
        # Fork and exec an ssh-agent to store the ssh-keys
        sshSocket = "-".join(["/tmp/ssh-agent",self.pid])
        env = os.environ
        agentOutput = subprocess.check_output( ['ssh-agent','-a',sshSocket], env=env)
        try:
            m = re.search( '(?<=SSH_AGENT_PID=)\d+', agentOutput,flags=re.MULTILINE)
            childPID = int(m.group(0))
        except Exception, e:
            raise Exception( "Could not parse out SSH_AGENT_PID from ssh-agent output: %s" % e)
        env['SSH_AUTH_SOCK'] = sshSocket
        subprocess.check_output( ['ssh-add',self.filesDelete[0]], env=env)
        t = biokbase.auth.Token(user_id="kbasetest", sshagent_keyname=self.filesDelete[0])
        self.assertIsInstance(t,biokbase.auth.Token,msg="Should be able to initialize token with user_id, sshagent_keyname")
        self.assertTrue(t.token,msg="Should have a token from sshagent_keyname initialization")
        # test default use of ssh-agent key
        t = biokbase.auth.Token(user_id="kbasetest")
        self.assertIsInstance(t,biokbase.auth.Token,msg="Should be able to initialize token with user_id, default sshagent key")
        self.assertTrue(t.token,msg="Should have a token from sshagent_keyname initialization")
        # Okay, kill the ssh-agent and move on
        os.kill(childPID,signal.SIGHUP)

class testAuthUser( unittest.TestCase):

    def setUp(self):
        pass

    def testNull(self):
        self.assertTrue( True, "Dummy test method")

if __name__ == '__main__':
    unittest.main()

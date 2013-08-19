import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.matchers.JUnitMatchers.*;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;

import javax.net.ssl.HttpsURLConnection;

import us.kbase.auth.AuthService;
import us.kbase.auth.AuthToken;
import us.kbase.auth.AuthUser;
import us.kbase.auth.AuthException;
import us.kbase.auth.TokenCache;
import us.kbase.auth.TokenExpiredException;
import us.kbase.auth.TokenFormatException;

public class AuthServiceTest {
	private static final String TEST_UID = "kbasetest";
	private static final String TEST_PW = System.getProperty("test.user.password");

	private static final String FULL_NAME = "KBase Test Account";
	private static final String EMAIL = "sychan@lbl.gov";
	private static final boolean IS_SYSADMIN = false;
	private static final boolean IS_OPT_IN = false;
	private static final String[] GROUPS = { "kbase_test", "kbase_test_users", "kbase_users2", "kbase_staff", "kbase_users" };
	private static final boolean EMAIL_VALID = true;
	private static final List<AuthToken> someTokens = new ArrayList<AuthToken>();
	private static final List<AuthToken> uncachedTokens = new ArrayList<AuthToken>();

	// Fetched before any tests are run - this test user is then used in the various POJO tests.
	private static AuthUser testUser = null;


	@BeforeClass
	public static void loginTestUser() throws UnsupportedEncodingException {
		System.out.println("Setting up test user for AuthUser and AuthToken testing...");
		try {
			testUser = AuthService.login(TEST_UID, TEST_PW);
			int tokens = 5;
			for(int i = 0; i < tokens; i++) {
				System.out.println("Getting token " + (i + 1) + "/" + tokens);
				someTokens.add(AuthService.login(TEST_UID, TEST_PW).getToken());
			}
			tokens = 2;
			for(int i = 0; i < tokens; i++) {
				System.out.println("Getting uncached token " + (i + 1) + "/" + tokens);
				uncachedTokens.add(getUncachedToken());
			}
		}
		catch (Exception e) {
			System.out.println("Setup failed to log in a test user for AuthUser and AuthToken tests!");
			System.out.println("Not running any tests!");
			System.out.println(e);
			System.exit(0);
		}
		System.out.println("Done! Beginning testing....");
	}
	
	public static AuthToken getUncachedToken() throws IOException, AuthException {
		String dataStr = "user_id=" + URLEncoder.encode(TEST_UID, "UTF-8") + 
				 "&password=" + URLEncoder.encode(TEST_PW, "UTF-8") + 
				 "&cookie=1&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";
		HttpsURLConnection conn = (HttpsURLConnection) AuthService.getServiceUrl().openConnection();
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		conn.setRequestProperty("Content-Length", String.valueOf(dataStr.getBytes().length));
		conn.setRequestProperty("Content-Language", "en-US");
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setDoInput(true);
		conn.setUseCaches(false);
		
		// Write out the POST data.
		DataOutputStream writer = new DataOutputStream(conn.getOutputStream());
		writer.writeBytes(dataStr);
		writer.flush();
		writer.close();
		
		// If we don't have a happy response code, throw an exception.
		int responseCode = conn.getResponseCode();
		if (responseCode != 200) {
			conn.disconnect();
			throw new AuthException("Login failed! Server responded with code " + responseCode + " " + conn.getResponseMessage());
		}

		/** Encoding the HTTP response into JSON format */
		BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

		return new ObjectMapper().readValue(br, AuthUser.class).getToken();
	}

	@AfterClass
	public static void cleanup() {
		System.out.println("Done testing!");
	}
	
	//test tokencache
	@Test
	public void tokenCacheDropsOldTokens() throws TokenExpiredException, InterruptedException {
		TokenCache tc = new TokenCache(2, 4);
		tc.putValidToken(someTokens.get(0));
		Thread.sleep(50);
		tc.putValidToken(someTokens.get(1));
		Thread.sleep(50);
		assertTrue("failure - cache missing tokens", tc.hasToken(someTokens.get(0)));
		tc.putValidToken(someTokens.get(2));
		Thread.sleep(50);
		tc.putValidToken(someTokens.get(3));
		Thread.sleep(50);
		assertTrue("failure - cache missing tokens", tc.hasToken(someTokens.get(0)));
		tc.putValidToken(someTokens.get(4));
		boolean[] expected = {true, false, false, false, true};
		for (int i = 0; i < expected.length; i++) {
			assertEquals("failure - cache retained wrong tokens", expected[i], tc.hasToken(someTokens.get(i)));
			
		}
	}
	
	@Test(expected = TokenExpiredException.class)
	public void tokenCacheRejectsExpiredTokens() throws Exception {
		TokenCache tc = new TokenCache(1, 2);
		AuthToken token = new AuthToken(testUser.getToken().toString(), 0);
		tc.putValidToken(token);
	}
	
	public void tokenCacheDropsExpiredTokens() throws Exception {
		TokenCache tc = new TokenCache(2, 2);
		tc.putValidToken(someTokens.get(0));
		Thread.sleep(50);
		tc.putValidToken(someTokens.get(1));
		Thread.sleep(50);
		AuthToken t = new AuthToken(someTokens.get(0).toString(), 0);
		try {
			tc.hasToken(t);
		} catch (TokenExpiredException e) {}
		tc.putValidToken(someTokens.get(3));
		boolean[] expected = {false, true, true};
		for (int i = 0; i < expected.length; i++) {
			assertEquals("failure - cache retained wrong tokens", expected[i], tc.hasToken(someTokens.get(i)));
			
		}
	}

	// test AuthToken POJO stuff - make sure all fields are non-null
	@Test
	public void testCreateTokenFromString() throws TokenFormatException {
		AuthToken token = new AuthToken(testUser.getTokenString());
		org.junit.Assert.assertNotNull("failure - unable to create a token from a string", token);
	}

	@Test
	public void testGetTokenUserName() {
		org.junit.Assert.assertNotNull("failure - user name is null", testUser.getToken().getUserName());
	}

	@Test
	public void testGetTokenId() {
		org.junit.Assert.assertNotNull("failure - token ID is null", testUser.getToken().getTokenId());
	}

	@Test
	public void testGetTokenClientId() {
		org.junit.Assert.assertNotNull("failure - client ID is null", testUser.getToken().getClientId());
	}

	@Test
	public void testGetTokenSigningSubject() {
		org.junit.Assert.assertNotNull("failure - signing subject is null", testUser.getToken().getSigningSubject());
	}

	@Test
	public void testGetTokenSignature() {
		org.junit.Assert.assertNotNull("failure - token signature is null", testUser.getToken().getSignature());
	}

	@Test
	public void testGetTokenIssue() {
		org.junit.Assert.assertFalse("failure - issue time is zero", testUser.getToken().getIssueDate().getTime() == 0);
	}

	@Test
	public void testGetTokenType() {
		org.junit.Assert.assertNotNull("failure - token type is null", testUser.getToken().getTokenType());
	}

	@Test
	public void testGetTokenData() {
		org.junit.Assert.assertNotNull("failure - token data is null", testUser.getToken().getTokenData());
	}

	@Test
	public void testIsTokenExpired() {
		// This is a brand new token. It shouldn't be expired.
		org.junit.Assert.assertFalse("failure - new token is expired", testUser.getToken().isExpired());
	}
	
	@Test
	public void testTokenExpires() throws Exception {
		// on some machines the token is already expired by the time you get it if you give <= 5s to expire
		AuthToken token1 = AuthService.login(TEST_UID, TEST_PW, 5).getToken();
		Thread.sleep(10000); //Globus seems to be able to issue tokens in the future and teleport them several seconds into the past
							//or java Calendar is off by a second or two
		AuthToken token2 = new AuthToken(testUser.getToken().toString(), 2);
		assertTrue("failure - token should be expired by now", token1.isExpired());
		org.junit.Assert.assertTrue("failure - token should be expired by now", token2.isExpired());
	}

	@Test
	public void testToString() {
		org.junit.Assert.assertNotNull("failure - token string is null", testUser.getToken().toString());
	}
	// done with AuthToken POJO tests.


	// test AuthUser POJO stuff - make sure all fields are non-null, and profile matches up.
	@Test
	public void testGetUserName() {
		org.junit.Assert.assertEquals("failure - incorrect user name", TEST_UID, testUser.getUserId());
	}

	@Test
	public void testGetUserFullName() {
		org.junit.Assert.assertEquals("failure - incorrect user name", FULL_NAME, testUser.getFullName());
	}

	@Test
	public void testIsUserSysAdmin() {
		org.junit.Assert.assertTrue("failure - incorrect SysAdmin status", testUser.isSystemAdmin() == IS_SYSADMIN);
	}

	@Test
	public void testIsUserOptIn() {
		org.junit.Assert.assertTrue("failure - incorrect OptIn status", testUser.hasOptIn() == IS_OPT_IN);
	}

	@Test
	public void testUserHasValidatedEmail() {
		org.junit.Assert.assertTrue("failure - incorrect email validation status", testUser.isEmailValidated() == EMAIL_VALID);
	}

	@Test
	public void testUserEmail() {
		org.junit.Assert.assertEquals("failure - incorrect email address", EMAIL, testUser.getEmail());
	}

	@Test
	public void testUserHasToken() {
		org.junit.Assert.assertNotNull("failure - user doesn't have a token", testUser.getToken());
	}

	@Test
	public void testUserHasSessionId() {
		org.junit.Assert.assertNotNull("failure - user doesn't have a session id", testUser.getSessionId());
	}

	@Test
	public void testUserGroups() {
		org.junit.Assert.assertThat(testUser.getGroups(), hasItems(GROUPS));
	}
	// done with AuthUser tests.


	// test AuthService methods
	@Test
	public void testDefaultServiceUrl() {
		org.junit.Assert.assertNotNull("failure - null default auth service URL", AuthService.getServiceUrl());
	}

	@Test
	public void testValidServiceUrlChange() throws Exception{
		URL oldUrl = AuthService.getServiceUrl();

		// valid url
		URL newUrl = new URL("https://kbase.us/services/authorization/Sessions/Login");
		
		org.junit.Assert.assertTrue("failure - setting a valid service url didn't work!", AuthService.setServiceUrl(newUrl));
		AuthService.setServiceUrl(oldUrl);
	}

	@Test
	public void testGetUserFromTokenObject() throws Exception {
		AuthToken t = new AuthToken(testUser.getToken().toString(), 400);
		AuthUser user = AuthService.getUserFromToken(t);
		org.junit.Assert.assertNotNull("failure - getting user from a token object returned a null user", user);
		assertEquals("failure - token expiration wasn't maintained", 400, user.getToken().getExpiryTime());
	}

	@Test
	public void testLogin() throws Exception {
		AuthUser user = AuthService.login(TEST_UID, TEST_PW);
		org.junit.Assert.assertNotNull("failure - logging in returned a null user", user);
	}
	
	@Test
	public void testLoginWithExpiry() throws Exception {
		AuthUser user = AuthService.login(TEST_UID, TEST_PW, 300);
		assertEquals("fail - wrong expiration lifetime", 300, user.getToken().getExpiryTime());
	}
	
	@Test
	public void testValidateTokenStr() throws AuthException, IOException {
		String tokenStr = testUser.getTokenString();
		org.junit.Assert.assertTrue("failure - valid token string didn't validate", AuthService.validateToken(tokenStr));
		tokenStr = uncachedTokens.get(0).toString();
		org.junit.Assert.assertTrue("failure - valid token object didn't validate", AuthService.validateToken(tokenStr));
	}

	@Test
	public void testValidateTokenObject() throws AuthException, IOException {
		AuthToken token = testUser.getToken();
		org.junit.Assert.assertTrue("failure - valid token object didn't validate", AuthService.validateToken(token));
		token = uncachedTokens.get(1);
		org.junit.Assert.assertTrue("failure - valid token object didn't validate", AuthService.validateToken(token));
	}

	// login with bad user/pw
	@Test(expected = AuthException.class)
	public void testFailLogin() throws Exception {
		AuthService.login("asdf", "asdf");
	}

	// try to verify a bad token
	@Test(expected = AuthException.class)
	public void testFailValidate() throws AuthException, IOException {
		AuthService.validateToken("asdf");
	}

	// try to parse a bad token
	@Test(expected = TokenFormatException.class)
	public void testFailCreateToken() throws TokenFormatException {
		new AuthToken("bad token!");
	}

	// finished with AuthService methods
}
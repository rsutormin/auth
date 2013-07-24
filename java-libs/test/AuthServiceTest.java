import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.matchers.JUnitMatchers.*;
import static org.hamcrest.CoreMatchers.*;
import java.util.Arrays;
import java.util.List;

import us.kbase.auth.AuthService;
import us.kbase.auth.AuthToken;
import us.kbase.auth.AuthUser;

public class AuthServiceTest {
	private static final String TEST_UID = "kbasetest";
	private static final String TEST_PW = "@Suite525";

	private static final String FULL_NAME = "KBase Test Account";
	private static final String EMAIL = "sychan@lbl.gov";
	private static final boolean IS_SYSADMIN = false;
	private static final boolean IS_OPT_IN = false;
	private static final String[] GROUPS = { "kbase_test", "kbase_test_users", "kbase_users2", "kbase_staff", "kbase_users" };
	private static final boolean EMAIL_VALID = true;

	// Fetched before any tests are run - this test user is then used in the various POJO tests.
	private static AuthUser testUser = null;


	@BeforeClass
	public static void loginTestUser() {
		System.out.println("doing pre set up");
		try {
			testUser = AuthService.login(TEST_UID, TEST_PW);
		}
		catch (Exception e) {
			System.out.println("Setup failed to log in a test user for AuthUser and AuthToken tests!");
			System.out.println("Not running any tests!");
			System.exit(0);
		}
	}

	// test AuthToken POJO stuff - make sure all fields are non-null
	@Test
	public void testCreateTokenFromString() throws Exception {
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
	public void testGetTokenExpiry() {
		org.junit.Assert.assertFalse("failure - expiration time is zero", testUser.getToken().getExpiry() == 0);
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
	public void testServiceUrlChange() {
		String oldUrl = AuthService.getServiceUrl();
		String newUrl = "https://kbase.us/testurl";
		AuthService.setServiceUrl(newUrl);
		org.junit.Assert.assertEquals("failure - new url isn't set properly", newUrl, AuthService.getServiceUrl());
		AuthService.setServiceUrl(oldUrl);
	}

	@Test
	public void testGetUserFromTokenObject() throws Exception {
		AuthUser user = AuthService.getUserFromToken(testUser.getToken());
		org.junit.Assert.assertNotNull("failure - getting user from a token object returned a null user", user);
	}

	@Test
	public void testGetUserFromTokenString() throws Exception {
		AuthUser user = AuthService.getUserFromToken(testUser.getTokenString());
		org.junit.Assert.assertNotNull("failure - getting user from a token string returned a null user", user);
	}

	@Test
	public void testLogin() throws Exception {
		AuthUser user = AuthService.login(TEST_UID, TEST_PW);
		org.junit.Assert.assertNotNull("failure - logging in returned a null user", user);
	}

	@Test
	public void testValidateTokenStr() throws Exception {
		String tokenStr = testUser.getTokenString();
		org.junit.Assert.assertTrue("failure - valid token string didn't validate", AuthService.validateToken(tokenStr));
	}

	@Test
	public void testValidateTokenObject() throws Exception {
		AuthToken token = testUser.getToken();
		org.junit.Assert.assertTrue("failure - valid token object didn't validate", AuthService.validateToken(token));
	}
	// finished with AuthService methods
}
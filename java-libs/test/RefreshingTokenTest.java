

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import us.kbase.auth.AuthToken;
import us.kbase.auth.RefreshingToken;

public class RefreshingTokenTest {
	
	private static String USER = "kbasetest";
	private static String PWD = System.getProperty("test.user.password");
	
	@Test
	public void refreshToken() throws Exception {
		RefreshingToken rt = new RefreshingToken(USER, PWD, 5);
		AuthToken t1 = rt.getToken();
		AuthToken t2 = rt.getToken();
		assertThat("got same token immediately", t2.toString(), is(t1.toString()));
		Thread.sleep(2000); //wait 2s
		AuthToken t3 = rt.getToken();
		assertThat("got same token after 2s", t3.toString(), is(t1.toString()));
		Thread.sleep(4000); //wait 4s
		AuthToken t4 = rt.getToken();
		assertTrue("token different after 6s", !t4.toString().equals(t1.toString()));
	}
	
	//TODO bad args tests
}

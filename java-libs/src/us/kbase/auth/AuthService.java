package us.kbase.auth;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;

/**
 * A fairly simple Auth service client for KBase, intended (at least initially) for use with GLAMM.
 * Usage:
 * 
 * AuthUser user = AuthService.login(user, password);
 * if (AuthService.validateToken(user.getToken())) {
 * 		// There's a valid token! Return the valid user, or just the token, and move along.
 * }
 * 
 * Thus, this provides code for a user to log in to KBase, retrieve a valid Auth token, and
 * optionally validate it.
 * 
 * @author wjriehl
 */
public class AuthService {
	private static String AUTH_URL = "https://www.kbase.us/services/authorization";
	private static String AUTH_LOGIN_PATH = "/Sessions/Login";
	private static TokenCache tc = new TokenCache();
	
	/**
	 * Logs in a user and returns an AuthUser object, which is more or less a POJO containing basic user attributes,
	 * along with the generated AuthToken.
	 * 
	 * @param user the username
	 * @param pw the password
	 * @param expiry the desired expiration time for the token in seconds.
	 * @return an AuthUser that has been successfully logged in.
	 * @throws AuthException if the credentials are invalid, or if there is a problem communicating with the server.
	 */
	public static AuthUser login(String userName, String password, long expiry) throws AuthException {
		// This is the data that will be POSTed to the service.
		// By default (not sure if we *really* need to change it), it fetches all the fields.
		try {
			String dataStr = "user_id=" + URLEncoder.encode(userName, "UTF-8") + 
							 "&password=" + URLEncoder.encode(password, "UTF-8") + 
							 "&cookie=1&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";
			return fetchUser(dataStr, expiry);
		}
		catch (UnsupportedEncodingException e) {
			throw new RuntimeException("An unexpected URL encoding exception occurred: " + e.getLocalizedMessage());
		}
		catch (IOException e) {
			throw new AuthException("An error occurred while parsing the authentication results: " + e.getLocalizedMessage());
		}
	}
	

	/**
	 * Logs in a user and returns an AuthUser object, which is more or less a POJO containing basic user attributes,
	 * along with the generated AuthToken.
	 * 
	 * @param user the username
	 * @param pw the password
	 * @return an AuthUser that has been successfully logged in.
	 * @throws AuthException if the credentials are invalid, or if there is a problem communicating with the server.
	 */
	public static AuthUser login(String userName, String password) throws AuthException {
		return login(userName, password, AuthToken.DEFAULT_EXPIRES);
	}

	/**
	 * Given an AuthToken object for a logged in user, this returns the AuthUser object representing that user's
	 * profile.
	 * 
	 * @param token the token
	 * @return an AuthUser associated with the given token.
	 * @throws AuthException if the token is malformed or invalid, or if an error occurs while communicating
	 * with the server.
	 */
	public static AuthUser getUserFromToken(AuthToken token) throws AuthException {
		String dataStr = "token=" + token.toString() +
				 "&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";

		try {
			return fetchUser(dataStr, token.getExpiryTime());
		}
		catch (IOException e) {
			throw new AuthException("An error occurred while parsing the authentication results: " + e.getLocalizedMessage());
		}
	}
	
	/**
	 * Given a data str, describing URL-encoded fields for the auth server, this attempts to authenticate the user
	 * with KBase servers.
	 * 
	 * @param dataStr 
	 * @return an AuthUser that has been authenticated with KBase
	 * @throws AuthException if the auth credentials are invalid or if the login URL is incorrect.
	 */
	private static AuthUser fetchUser(String dataStr, long expiry) throws AuthException,
																		  IOException {
		// Start with a null user - if the mapper fails for some reason, we know it's
		// still null (and not uninitialized), and can throw a proper exception.
		AuthUser user = null;

		try {
			// Build the connection project and set it up.
			HttpsURLConnection conn = (HttpsURLConnection) new URL(AUTH_URL + AUTH_LOGIN_PATH).openConnection();
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
	
			user = new ObjectMapper().readValue(br, AuthUser.class);
			if (user == null) { // if still null, throw an exception 
				throw new AuthException("Unable to construct a user object from login results!");
			}
			user.getToken().setExpiryTime(expiry);
			tc.putValidToken(user.getToken());

			br.close();
			conn.disconnect();
			return user;
		}
		catch (UnsupportedEncodingException e) {
			throw new RuntimeException("An unexpected encoding exception occurred: " + e.getLocalizedMessage());
		}
		catch (MalformedURLException e) {
			throw new RuntimeException("An exception occurred while connecting to the auth service URL: " + e.getLocalizedMessage());
		}
	}
	
	/**
	 * Given a String representation of an auth token, this validates it against its source in Globus Online.
	 * 
	 * @param tokenStr the token string retrieved from KBase
	 * @return true if the token's valid, false otherwise
	 * @throw AuthException if there is a problem parsing the token or the server response, or if the token's 
	 * verification URL is invalid.
	 */
	public static boolean validateToken(String tokenStr) throws TokenFormatException,
																TokenExpiredException, 
																IOException {
		AuthToken token = new AuthToken(tokenStr);
		return validateToken(token);
	}
	
	/**
	 * This validates a KBase Auth token, and returns true or if valid or false if not.
	 * If the token has expired, it throws a TokenExpiredException.
	 *
	 * @param token
	 * @return true if the token's valid, false otherwise
	 * @throws TokenExpiredException if the token is expired (it might be otherwise valid)
	 * @throws IOException if there's a problem communicating with the back end validator.
	 */
	public static boolean validateToken(AuthToken token) throws TokenExpiredException,
																IOException {		

		// If it's expired, then it's invalid, and we throw an exception
		if(token.isExpired()) {
			throw new TokenExpiredException("token expired");
		}
		
		// If it's in the cache, then it's valid.
		if(tc.hasToken(token)) {
			return true;
		}

		// Otherwise, fetch the user from the Auth Service.
		// If the user is there, then cache this token and return that it's valid.
		try {
			// if we get a user back (and not an exception), then the token is valid.
			AuthUser user = getUserFromToken(token);
			tc.putValidToken(token);
			return true;
		} catch (AuthException e) {
			// if we get an exception, then an authentication error happened - that's an invalid token.
			return false;
		}
	}

	/**
	 * Disables SSL certificate validation.
	 * 
	 * Once upon a time, we had issues getting the KBase SSL certificate renewed. This isn't a big deal for a web
	 * user - just click through the "Hey, this isn't valid!" page. But going over https would make the Java
	 * HttpsURLConnection have a tizzy fit.
	 * 
	 * Running this method tells the HttpsURLConnection to ignore any certificate validation errors in any subsequent
	 * calls. So if the certificate has errors in the future, run this method before doing any service calls.
	 * 
	 * e.g.
	 * <code>
	 * AuthService.disableCertificateValidation();
	 * AuthService.login(<<credentials>>);
	 * </code>
	 */
	@SuppressWarnings("unused")
	private static void disableCertificateValidation() {
		TrustManager[] trustAllCerts = new TrustManager[] {
			new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}
				public void checkClientTrusted(X509Certificate[] certs, String authType) {}
				public void checkServerTrusted(X509Certificate[] certs, String authType) {}
			}
		};
		
		HostnameVerifier hv = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) { return true; }
		};
		
		try {
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			HttpsURLConnection.setDefaultHostnameVerifier(hv);
		} catch (Exception e) {}
	}
	
	/**
	 * Returns the current URL to which the service is pointing.
	 * @return the current URL for the service
	 */
	public static String getServiceUrl() {
		return AUTH_URL;
	}
	
	/**
	 * Sets the URL that the service should point to. This is the base URL, e.g.:
	 * https://kbase.us/services/authorization
	 * NOT
	 * https://kbase.us/services/authorization/Sessions/Login
	 * 
	 * @param url
	 */
	public static void setServiceUrl(String url) {
		if (url != null && url.length() > 0 && url.startsWith("http"))
			AUTH_URL = url;
	}
	
	// Main for testing.
	// TODO - make some JUnit tests.
	public static void main(String[] args) {
		try {
			AuthUser user = AuthService.login("kbasetest", "@Suite525");
			boolean validated = AuthService.validateToken(user.getToken());
			System.out.println(user.toString() + "\nValidated token? " + validated);
			
			AuthUser user2 = AuthService.getUserFromToken(user.getToken());
			System.out.println(user2.toString());
			System.out.println(user2.getToken().getTokenData());
			
			System.out.println(user2.getToken().isExpired());

			AuthService.login("asdf", "jkl;");
		} 
		catch (Exception e) {
			System.out.println(e.getLocalizedMessage());
		}
	}
	
}

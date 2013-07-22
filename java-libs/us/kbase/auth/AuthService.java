package us.kbase.auth;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
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
	
	/**
	 * Logs in a user and returns an AuthUser object, which is more or less a POJO containing basic user attributes,
	 * along with the generated AuthToken.
	 * 
	 * @param user
	 * @param pw
	 * @return an AuthUser that has been successfully logged in.
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws IOException
	 */
	public static AuthUser login(String userName, String password) throws UnsupportedEncodingException, 
														 				  NoSuchAlgorithmException,
														 		   		  KeyManagementException,
														 		   		  IOException {
		// This is the data that will be POSTed to the service.
		// By default (not sure if we *really* need to change it), it fetches all the fields.
		String dataStr = "user_id=" + URLEncoder.encode(userName, "UTF-8") + 
						 "&password=" + URLEncoder.encode(password, "UTF-8") + 
						 "&cookie=1&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";
		
		
		return fetchUser(dataStr);
	}

	/**
	 * Given a token for a logged in user, returns the AuthUser object representing that user's profile.
	 *
	 * @param token
	 * @return an AuthUser associated with the given token.
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws IOException
	 */
	public static AuthUser getUserFromToken(String token) throws UnsupportedEncodingException,
																 NoSuchAlgorithmException,
																 KeyManagementException,
																 IOException {
		String dataStr = "token=" + token +
						 "&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";
		
		return fetchUser(dataStr);
	}

	/**
	 * Given an AuthToken object for a logged in user, this returns the AuthUser object representing that user's
	 * profile.
	 * 
	 * @param token
	 * @return an AuthUser associated with the given token.
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws IOException
	 */
	public static AuthUser getUserFromToken(AuthToken token) throws UnsupportedEncodingException,
																	NoSuchAlgorithmException,
																	KeyManagementException,
																	IOException {
		
		String dataStr = "token=" + token.toString() +
						 "&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";
		
		return fetchUser(dataStr);
	}
	
	private static AuthUser fetchUser(String dataStr) throws UnsupportedEncodingException,
															 NoSuchAlgorithmException,
															 KeyManagementException,
															 IOException {
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
			throw new IOException("Login failed! Server responded with code " + responseCode + " " + conn.getResponseMessage());
		}

		/** Encoding the HTTP response into JSON format */
		BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		
		// Start with a null user - if the mapper fails for some reason, we know it's
		// still null (and not uninitialized), and can throw a proper exception.
		AuthUser user = null;
		user = new ObjectMapper().readValue(br, AuthUser.class);

		br.close();
		conn.disconnect();
		
		// In the end, return the user.
		if (user == null) { // if still null, throw an exception 
			throw new IOException("Unable to construct a user object from login results!");
		}
		return user;
		
	}
	
	
	/**
	 * This validates a KBase Auth token, and returns true or if valid or false if not.
	 * 
	 * It works in a few steps:
	 * 1. Check the token format, throw IOException if the format's wrong.
	 * 2. Extract the 'token' part and the signature.
	 * 3. Get the public key from the 'SigningSubject' part of the token.
	 * 4. Do the sha1-RSA comparison.
	 * 5. Return the result of the comparison
	 * 
	 * Most of this is taken from KBaseAuthValidateToken.java, written by Shuchu Han, as part of the Persistent Store code.
	 * So, thanks!
	 * @param token
	 * @return true if the token's valid, false otherwise
	 */
	public static boolean validateToken(AuthToken token) throws IOException, 
																NoSuchAlgorithmException, 
																KeyManagementException, 
																InvalidKeyException, 
																SignatureException {
		
		/** now HTTPS the SigningSubject of input Token */
		URL validationUrl = new URL(token.getSigningSubject());
		
		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { 
			new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() { 
					return new X509Certificate[0]; 
				}
				public void checkClientTrusted(X509Certificate[] certs, String authType) {}
				public void checkServerTrusted(X509Certificate[] certs, String authType) {}
			}
		};
		
		// Ignore differences between given hostname and certificate hostname
		HostnameVerifier hv = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) { return true; }
		};
		
		// Install the all-trusting trust manager
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier(hv);
		
		/** make the request to Authentication server */
		HttpsURLConnection conn = (HttpsURLConnection) validationUrl.openConnection(); 
		InputStream in = conn.getInputStream();
		
		/** Encoding the HTTP response into JSON format */
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		ObjectMapper m = new ObjectMapper();
		JsonNode jn = m.readTree(br);
		JsonNode jd = jn.get("pubkey");

		in.close();
		conn.disconnect();
		
		/** now get the public key and do the verify */
		Security.addProvider(new BouncyCastleProvider());
		PEMReader pemReader = new PEMReader(new StringReader(jd.getTextValue().replace("\\n","\n")));
		RSAPublicKey pubKey = (RSAPublicKey) pemReader.readObject();
		pemReader.close();

		/** http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyFactoryEx */
		Signature s = Signature.getInstance("SHA1withRSA");
		
		s.initVerify(pubKey);

		/** update the data
		 * 
		 *	SHA-1 (and all other hashing algorithms) return binary data. That means that (in Java) they produce a byte[].
		 *  That byte array does not represent any specific characters, which means you can't simply turn it into a String 
		 *  like you did.If you need a String, then you have to format that byte[] in a way that can be represented as 
		 *  a String (otherwise, just keep the byte[] around).Two common ways of representing arbitrary byte[] as printable
		 *  characters are BASE64 or simple hex-Strings (i.e. representing each byte by two hexadecimal digits). 
		 *  It looks like you're trying to produce a hex-String. There's also another pitfall: if you want to get the SHA-1 
		 *  of a Java String, then you need to convert that String to a byte[] first (as the input of SHA-1 is a byte[] as well). 
		 *  If you simply use myString.getBytes() as you showed, then it will use the platform default encoding and as such 
		 *  will be dependent on the environment you run it in (for example it could return different data based on the 
		 *  language/locale setting of your OS).A better solution is to specify the encoding to use for the String-to-byte[] 
		 *  conversion like this: myString.getBytes("UTF-8"). Choosing UTF-8 (or another encoding that can represent every 
		 *  unicode character) is the safest choice here.
		 */
		byte[] sig_data_byte = token.getTokenData().getBytes("UTF-8");
		s.update(sig_data_byte);

		/**
		* The equivalent of Perl 's pack "H*", $vartoconvert in Java is :
		* javax.xml.bind.DatatypeConverter.parseHexBinary(hexadecimalString);.
		* For more information on this, I think it is recommended to read 
		* DatatypeConverter class' reference from JavaDocs. 
		*/
		byte[] sig_byte = javax.xml.bind.DatatypeConverter.parseHexBinary(token.getSignature());
		
		/** verification of signature*/
		boolean result = s.verify(sig_byte);
	
		return result;
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
			
			AuthUser user2 = AuthService.getUserFromToken(user.getToken().toString());
			System.out.println(user2.toString());
			System.out.println(user2.getToken().getTokenData());
			
			System.out.println(user2.getToken().isExpired());
		} catch (IOException e) {
			// handle IOException
			System.out.println(e.getLocalizedMessage());
		} catch (Exception e) {
			System.out.println(e.getLocalizedMessage());
		}
		
	}
	
}

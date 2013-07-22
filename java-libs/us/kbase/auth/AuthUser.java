package us.kbase.auth;

import java.io.IOException;
import java.util.List;

import org.codehaus.jackson.annotate.JsonProperty;

/**
 * A simple class defining an authenticated user. This contains a series of
 * getters and setters for exchanging user information.
 * 
 * Mostly, this is used for unmarshalling an authentication response from KBase.
 * @author wjriehl
 *
 */
public class AuthUser {
	private boolean emailValidated = false;
	private String userId = null;
	private String email = null;
	private List<String> groups = null;
	private String fullName = null;
	private String kbaseSession = null;
	private String errorMessage = null;
	private AuthToken token = null;
	private boolean optIn = false;
	private boolean systemAdmin = false;

	public AuthUser() { }

	@JsonProperty("opt_in")
	public boolean hasOptIn() {
		return optIn;
	}
	
	@JsonProperty("opt_in")
	public void setOptIn(boolean optIn) {
		this.optIn = optIn;
	}
	
	@JsonProperty("system_admin")
	public boolean isSystemAdmin() {
		return systemAdmin;
	}
	
	@JsonProperty("system_admin")
	public void setSystemAdmin(boolean systemAdmin) {
		this.systemAdmin = systemAdmin;
	}
	
	@JsonProperty("verified")
	public boolean isEmailValidated() {
		return emailValidated;
	}
	@JsonProperty("verified")
	public void setEmailValidated(boolean emailValidated) {
		this.emailValidated = emailValidated;
	}

	@JsonProperty("user_id")
	public String getUserId() {
		return userId;
	}
	@JsonProperty("user_id")
	public void setUserId(String userId) {
		this.userId = userId;
	}
	
	@JsonProperty("email")
	public String getEmail() {
		return email;
	}
	@JsonProperty("email")
	public void setEmail(String email) {
		this.email = email;
	}

	@JsonProperty("token")
	public void setToken(String tokenStr) throws IOException {
		this.token = new AuthToken(tokenStr);
	}
	
	/**
	 * Returns the token associated with this user as the AuthToken object.
	 * @return an AuthToken object.
	 */
	@JsonProperty("token")
	public AuthToken getToken() {
		return token;
	}
	
	public void setToken(AuthToken token) {
		this.token = token;
	}

	/**
	 * Returns the token associated with this user as its original string.
	 * @return an authentication token String.
	 */
	public String getTokenString() {
		return token.toString();
	}
	
	@JsonProperty("groups")
	public List<String> getGroups() {
		return groups;
	}
	
	@JsonProperty("groups")
	public void setGroups(List<String> groups) {
		this.groups = groups;
	}

	@JsonProperty("name")
	public String getFullName() {
		return fullName;
	}
	
	@JsonProperty("name")
	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	@JsonProperty("kbase_sessionid")
	public String getSessionId() {
		return kbaseSession;
	}
	@JsonProperty("kbase_sessionid")
	public void setSessionId(String kbaseSession) {
		this.kbaseSession = kbaseSession;
	}
	
	@JsonProperty("error_msg")
	public String getErrorMessage() {
		return errorMessage;
	}
	@JsonProperty("error_msg")
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("user id: " + userId + "\n");
		buf.append("full name: " + fullName + "\n");
		buf.append("email validated: " + emailValidated + "\n");
		buf.append("email: " + email + "\n");
		buf.append("groups: " + groups + "\n");
		buf.append("session id: " + kbaseSession + "\n");
		buf.append("token: " + token.toString() + "\n");
		buf.append("sysadmin: " + systemAdmin + "\n");
		buf.append("opt_in: " + optIn + "\n");
		return buf.toString();
	}
}
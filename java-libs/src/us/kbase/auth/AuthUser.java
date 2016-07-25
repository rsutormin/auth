package us.kbase.auth;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A simple class defining an authenticated user. This contains a series of
 * getters and setters for exchanging user information.
 * 
 * Mostly, this is used for unmarshalling an authentication response from KBase.
 * @author wjriehl
 * @author gaprice@lbl.gov
 *
 */
public class AuthUser {
	@JsonProperty("verified")
	private boolean emailValidated = false;
	@JsonProperty("user_id")
	private String userId = null;
	private String email = null;
	private List<String> groups = null;
	private String fullName = null;
	@JsonProperty("kbase_sessionid")
	private String kbaseSession = null;
	private String errorMessage = null;
	private AuthToken token = null;
	@JsonProperty("opt_in")
	private boolean optIn = false;
	@JsonProperty("system_admin")
	private boolean systemAdmin = false;

	private AuthUser() { }

	@JsonProperty("opt_in")
	public boolean hasOptIn() {
		return optIn;
	}
	
	@JsonProperty("system_admin")
	public boolean isSystemAdmin() {
		return systemAdmin;
	}
	
	@JsonProperty("verified")
	public boolean isEmailValidated() {
		return emailValidated;
	}
	@JsonProperty("user_id")
	public String getUserId() {
		return userId;
	}
	@JsonProperty("email")
	public String getEmail() {
		return email;
	}
	
	/**
	 * Returns the token associated with this user as the AuthToken object.
	 * @return an AuthToken object.
	 */
	@JsonProperty("token")
	public AuthToken getToken() {
		return token;
	}
	

	/**
	 * Returns the token associated with this user as its original string.
	 * @return an authentication token String.
	 */
	public String getTokenString() {
		return token.getToken();
	}
	
	@JsonProperty("groups")
	public List<String> getGroups() {
		return groups;
	}
	

	@JsonProperty("name")
	public String getFullName() {
		return fullName;
	}
	
	@JsonProperty("kbase_sessionid")
	public String getSessionId() {
		return kbaseSession;
	}

	@JsonProperty("error_msg")
	public String getErrorMessage() {
		return errorMessage;
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
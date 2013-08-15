package us.kbase.auth;

import java.lang.Exception;

public class AuthException extends Exception {
	public AuthException() {
		super();
	}

	public AuthException(String exception) {
		super(exception);
	}
}
package us.kbase.auth;

import java.lang.Exception;

public class AuthException extends Exception {

	private static final long serialVersionUID = 1L;

	public AuthException() {
		super();
	}

	public AuthException(String exception) {
		super(exception);
	}
}
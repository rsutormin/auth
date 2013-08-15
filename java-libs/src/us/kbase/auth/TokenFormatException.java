package us.kbase.auth;

public class TokenFormatException extends TokenException {

	private static final long serialVersionUID = 1L;

	public TokenFormatException() {
		super();
	}

	public TokenFormatException(String exception) {
		super(exception);
	}
}
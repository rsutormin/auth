package us.kbase.auth;

public class TokenExpiredException extends TokenException {

	private static final long serialVersionUID = 1L;

	public TokenExpiredException() {
		super();
	}

	public TokenExpiredException(String exception) {
		super(exception);
	}
}
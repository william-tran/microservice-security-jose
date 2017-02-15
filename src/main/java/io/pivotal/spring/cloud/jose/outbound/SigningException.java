package io.pivotal.spring.cloud.jose.outbound;

public class SigningException extends RuntimeException {
	private static final long serialVersionUID = 4548863923321703813L;

	public SigningException(String message, Throwable cause) {
		super(message, cause);
	}

	public SigningException(String message) {
		super(message);
	}

}

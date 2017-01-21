package io.pivotal.spring.cloud.security.inbound;

public class VerificationException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6096646823010314277L;

	public VerificationException(String message, Throwable cause) {
		super(message, cause);
	}

	public VerificationException(String message) {
		super(message);
	}

}

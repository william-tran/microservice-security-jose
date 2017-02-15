package io.pivotal.spring.cloud.jose.inbound;

public class PolicyException extends RuntimeException {

	private static final long serialVersionUID = -7132544053368609464L;

	public PolicyException(String message, Throwable cause) {
		super(message, cause);
	}

	public PolicyException(String message) {
		super(message);
	}

}

package io.pivotal.spring.cloud.jose.inbound;

public class ReplayException extends RuntimeException {

	private static final long serialVersionUID = -4917471876253946482L;

	public ReplayException(String message, Throwable cause) {
		super(message, cause);
	}

	public ReplayException(String message) {
		super(message);
	}

}

package io.pivotal.spring.cloud.jose.inbound;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.Getter;

@Getter
public class VerifiedMessage {

	public VerifiedMessage(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack, String contentType,
			byte[] body) {
		this.initialTokenClaims = Collections.unmodifiableMap(initialTokenClaims);
		this.callStack = Collections.unmodifiableList(callStack);
		this.contentType = contentType;
		this.body = body;
	}

	public VerifiedMessage(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
		this(initialTokenClaims, callStack, null, null);
	}

	private final Map<String, Object> initialTokenClaims;
	private final List<SelfIssuedToken> callStack;
	private final String contentType;
	private final byte[] body;

}

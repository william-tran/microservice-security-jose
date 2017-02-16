package io.pivotal.spring.cloud.jose.inbound;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.Getter;

@Getter
public class VerifiedMessage {

	public VerifiedMessage(String tokenChain, Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack, String contentType,
			byte[] body) {
		this.tokenChain = tokenChain;
		this.initialTokenClaims = initialTokenClaims != null ? Collections.unmodifiableMap(initialTokenClaims) : null;
		this.callStack = Collections.unmodifiableList(callStack);
		this.contentType = contentType;
		this.body = body;
	}

	public VerifiedMessage(String token, Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
		this(token, initialTokenClaims, callStack, null, null);
	}

	private final String tokenChain;
	private final Map<String, Object> initialTokenClaims;
	private final List<SelfIssuedToken> callStack;
	private final String contentType;
	private final byte[] body;

}

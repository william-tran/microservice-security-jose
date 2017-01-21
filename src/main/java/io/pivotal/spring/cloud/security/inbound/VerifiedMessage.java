package io.pivotal.spring.cloud.security.inbound;

import java.util.List;
import java.util.Map;

public class VerifiedMessage {
	
	public Map<String,Object> initialTokenClaims;
	public List<SelfIssuedToken> callStack;

	private String contentType;
	private byte[] body;
	
}

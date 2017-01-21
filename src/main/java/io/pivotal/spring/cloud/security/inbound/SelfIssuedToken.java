package io.pivotal.spring.cloud.security.inbound;

import java.util.Collections;
import java.util.Map;

import lombok.Getter;

@Getter
public class SelfIssuedToken {
	
	private final String audOfIssuer;
	private final Map<String,Object> claims;

	public SelfIssuedToken(String audOfIssuer, Map<String, Object> claims) {
		this.audOfIssuer = audOfIssuer;
		this.claims = Collections.unmodifiableMap(claims);
	}
}

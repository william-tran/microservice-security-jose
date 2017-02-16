package io.pivotal.spring.cloud.jose.inbound;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import io.pivotal.spring.cloud.jose.Constants;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class SelfIssuedToken {
	
	private final String audOfIssuer;
	private final Map<String,Object> claims;

	public SelfIssuedToken(String audOfIssuer, Map<String, Object> claims) {
		this.audOfIssuer = audOfIssuer;
		Object audClaim = claims.get(Constants.AUDIENCE_CLAIM);
		if (!(audClaim instanceof List)) {
			throw new IllegalArgumentException("aud must be a list");
		}
		List<?> audList = (List<?>) audClaim;
		if (audList.isEmpty()) {
			throw new IllegalArgumentException("aud cannot be empty");
		}
		if (audList.stream().anyMatch(aud -> !(aud instanceof String))) {
			throw new IllegalArgumentException("aud must be a list of String");
		}
		this.claims = Collections.unmodifiableMap(claims);
	}
	
	@SuppressWarnings("unchecked")
	public List<String> getAudience() {
		return (List<String>)claims.get(Constants.AUDIENCE_CLAIM);
	}
}

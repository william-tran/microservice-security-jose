package io.pivotal.spring.cloud.jose.inbound;

import java.util.Map;

public interface IntialTokenClaimsExtrator {
	
	Map<String,Object> extractVerifiedClaims(String token);

}

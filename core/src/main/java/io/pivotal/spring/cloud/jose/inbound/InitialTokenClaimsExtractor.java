package io.pivotal.spring.cloud.jose.inbound;

import java.util.Map;

public interface InitialTokenClaimsExtractor {
	
	Map<String,Object> extractVerifiedClaims(String token);

}

package io.pivotal.spring.cloud.jose.inbound;

import java.util.List;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class TokenPolicyChecker implements PolicyChecker {
	private final TokenPolicy tokenPolicy;

	@Override
	public void checkPolicy(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack)
			throws PolicyException {
		try {
			tokenPolicy.apply(initialTokenClaims, callStack);
		} catch (PolicyException e) {
			log.error("invocation did not adhere to policy", e);
			throw e;
		}
	}
	
}

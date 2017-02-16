package io.pivotal.spring.cloud.jose.inbound;

import java.util.List;
import java.util.Map;

import io.pivotal.spring.cloud.jose.inbound.TokenPolicy.Rule;

public class PolicyException extends RuntimeException {

	private static final long serialVersionUID = -7132544053368609464L;

	public PolicyException(String message, Throwable cause) {
		super(message, cause);
	}

	public PolicyException(String message) {
		super(message);
	}
	
	
	public PolicyException(int ruleListIndex, int ruleIndex, Rule rule, Map<String, Object> initialTokenClaims,
			List<SelfIssuedToken> callStack) {
		super(String.format("The invocation matched rule #%d of rule list #%d but failed its conditions.\n"
			+"callStack is %s\n"
			+"initialTokenClaims are %s\n"
			+"rule is %s"
		, ruleListIndex, ruleIndex, callStack, initialTokenClaims, rule));
	}

	
}

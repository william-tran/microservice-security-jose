/*
 * Copyright 2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

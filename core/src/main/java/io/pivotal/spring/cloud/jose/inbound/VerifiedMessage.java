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

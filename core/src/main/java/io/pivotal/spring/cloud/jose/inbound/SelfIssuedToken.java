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

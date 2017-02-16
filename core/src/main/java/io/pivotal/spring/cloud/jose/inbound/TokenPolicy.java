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

import static java.lang.Boolean.TRUE;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.pivotal.spring.cloud.jose.Constants;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
public class TokenPolicy {

	private List<RuleList> forEachOfTheFollowing;

	public void apply(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
		if (forEachOfTheFollowing == null || forEachOfTheFollowing.isEmpty()) {
			throw new PolicyException("no rule lists have been defined for this policy.");
		}
		for (int i = 0; i < forEachOfTheFollowing.size(); i++) {
			RuleList ruleList = forEachOfTheFollowing.get(i);
			ruleList.apply(i, initialTokenClaims, callStack);
		}
	}

	@Data
	public static class RuleList {
		private List<Rule> enforceTheFirstMatchingRule;

		public void apply(int ruleListIndex, Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
			if (enforceTheFirstMatchingRule == null || enforceTheFirstMatchingRule.isEmpty()) {
				throw new PolicyException("no rules have been defined for rule list index " + ruleListIndex);
			}
			for (int i = 0; i < enforceTheFirstMatchingRule.size(); i++) {
				Rule rule = enforceTheFirstMatchingRule.get(i);
				if (rule.matches(initialTokenClaims, callStack)) {
					if (rule.passes(initialTokenClaims, callStack)) {
						return;
					}
					throw new PolicyException(ruleListIndex, i, rule, initialTokenClaims, callStack);
				}
			}
		}
	}

	@Data
	public static class Rule {
		private Boolean anyToken;
		private NestedJwtTokenMatcher tokensThat;
		private NestedJwtTokenMatcher must;
		private Boolean mustBeRejected;

		public boolean matches(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
			return TRUE.equals(anyToken) || tokensThat.matches(initialTokenClaims, callStack);
		}

		public boolean passes(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
			return !TRUE.equals(mustBeRejected) && must.matches(initialTokenClaims, callStack);
		}

	}

	@Data
	public static class NestedJwtTokenMatcher {
		private ValueMatcher haveOperation;
		private IntialTokenMatcher haveInitialToken;
		private List<SelfIssuedTokenMatcher> comeFrom;
		private Map<String, ValueOrCollectionMatcher> haveClaim;
		private NestedJwtTokenMatcher or;
		private static final String DELIMITER = "|";

		public boolean matches(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
			if (callStack.isEmpty()) {
				return false;
			}
			boolean result = oneNotNull(haveOperation, haveInitialToken, comeFrom, haveClaim, or);
			SelfIssuedToken token = callStack.get(0);
			result = result && (haveOperation == null
					|| haveOperation.matches(token.getClaims().get(Constants.OPERATION_CLAIM)));
			result = result && (haveInitialToken == null || haveInitialToken.matches(initialTokenClaims));
			result = result && (haveClaim == null || matchesCustomClaims(haveClaim, token.getClaims()));
			result = result && (comeFrom == null || matchesCallStack(callStack));
			if (or != null) {
				result = result || or.matches(initialTokenClaims, callStack);
			}
			return result;
		}

		/**
		 * We first try to match on {@link SelfIssuedToken#getAudOfIssuer()},
		 * then AND additional matchers to the matched token, e.g. op, or custom
		 * claims.
		 * 
		 * @param callStack
		 * @return
		 */
		private boolean matchesCallStack(List<SelfIssuedToken> callStack) {
			// This implementation relies on converting the path to a string
			// with delimiters that can be regexed.
			// if that delimiter is used, fail with a error log

			for (SelfIssuedToken token : callStack) {
				if (token.getAudOfIssuer().contains(DELIMITER)) {
					log.error("delimiter {} used in audOfIssuer {}, failing match", DELIMITER, token.getAudOfIssuer());
					return false;
				}
			}
			String appPath = "";
			Map<Integer, Integer> stringLengthToStackIndex = new HashMap<>();
			for (int i = 0; i < callStack.size(); i++) {
				stringLengthToStackIndex.put(appPath.length(), i);
				SelfIssuedToken stackFrame = callStack.get(i);
				appPath = appPath + DELIMITER + stackFrame.getAudOfIssuer() + DELIMITER;
			}
			String appPathRegex = comeFrom.stream().map(this::getAppNameRegex).collect(Collectors.joining(""));
			Pattern appPathPattern = Pattern.compile(appPathRegex);
			Matcher matcher = appPathPattern.matcher(appPath);
			if (matcher.matches()) {
				for (int i = 0; i < comeFrom.size(); i++) {
					SelfIssuedTokenMatcher tokenMatcher = comeFrom.get(i);
					int groupStart = matcher.start(i + 1);
					if (groupStart != -1 && !TRUE.equals(tokenMatcher.anyNumberOfApps)) {
						Integer stackIndex = stringLengthToStackIndex.get(groupStart);
						SelfIssuedToken stackFrame = callStack.get(stackIndex);
						if (!tokenMatcher.matches(stackFrame)) {
							return false;
						}
					}
				}
				return true;
			}
			return false;
		}

		private String getAppNameRegex(SelfIssuedTokenMatcher tokenMatcher) {
			String appNameMatcher = "";
			String delim = "\\" + DELIMITER;
			String openDelim = "(" + delim;
			String closeDelim = delim + ")";

			if (TRUE.equals(tokenMatcher.anyNumberOfApps)) {
				appNameMatcher = "(.*)";
			} else if (TRUE.equals(tokenMatcher.anyApp)) {
				appNameMatcher = openDelim + "[^" + delim + "]+" + closeDelim;
			} else if (tokenMatcher.appName != null) {
				if (tokenMatcher.appName.equalTo != null) {
					appNameMatcher = openDelim + tokenMatcher.appName.equalTo + closeDelim;
				} else if (tokenMatcher.appName.matching != null) {
					appNameMatcher = openDelim + tokenMatcher.appName.matching + closeDelim;
				} else if (tokenMatcher.appName.oneOf != null) {
					appNameMatcher = tokenMatcher.appName.oneOf.stream()
							.map(Object::toString)
							.collect(Collectors.joining("|", openDelim+"(?:", ")"+closeDelim));
				}
			}

			if (TRUE.equals(tokenMatcher.optional)) {
				appNameMatcher = appNameMatcher + "?";
			}
			return appNameMatcher;
		}
	}

	@Data
	public static class ValueMatcher {
		private Object equalTo;
		private String matching;
		private List<Object> oneOf;

		public boolean matches(Object o) {
			boolean result = oneNotNull(equalTo, matching, oneOf);
			result = result && (equalTo == null || equalTo.equals(o));
			result = result && (matching == null || o.toString().matches(matching));
			result = result && (oneOf == null || oneOf.contains(o));
			return result;
		}

	}

	@Data
	public static class CollectionContainsMatcher {
		private Object value;
		private List<Object> oneOf;
		private List<Object> allOf;
		private List<Object> only;

		public boolean matches(Object o) {
			boolean result = oneNotNull(value, oneOf, allOf, only);
			if (!(o instanceof Collection)) {
				return false;
			}
			Collection<?> c = (Collection<?>) o;
			result = result && (value == null || c.contains(value));
			result = result && (oneOf == null || !Collections.disjoint(c, oneOf));
			result = result && (allOf == null || c.containsAll(allOf));
			result = result && (only == null || c.containsAll(only) && only.containsAll(c));
			return result;
		}
	}

	@Data
	public static class ValueOrCollectionMatcher {
		private CollectionContainsMatcher contains;
		private ValueMatcher is;

		public boolean matches(Object o) {
			boolean result = oneNotNull(contains, is);
			result = result && (contains == null || contains.matches(o));
			result = result && (is == null || is.matches(o));
			return result;
		}

	}

	@Data
	public static class IntialTokenMatcher {
		private ValueMatcher whereIssuerIs;
		private CollectionContainsMatcher whereScopeContains;
		private CollectionContainsMatcher whereAudienceContains;
		private Map<String, ValueOrCollectionMatcher> whereClaim;

		public boolean matches(Map<String, Object> initialTokenClaims) {
			boolean result = initialTokenClaims != null
					&& oneNotNull(whereIssuerIs, whereScopeContains, whereAudienceContains, whereClaim);

			result = result && (whereIssuerIs == null
					|| whereIssuerIs.equals(initialTokenClaims.get(Constants.ISSUER_CLAIM)));
			result = result && (whereScopeContains == null
					|| whereScopeContains.matches(initialTokenClaims.get(Constants.SCOPE_CLAIM)));
			result = result && (whereAudienceContains == null
					|| whereAudienceContains.matches(initialTokenClaims.get(Constants.AUDIENCE_CLAIM)));
			result = result && (whereAudienceContains == null
					|| whereAudienceContains.matches(initialTokenClaims.get(Constants.AUDIENCE_CLAIM)));
			result = result && (whereClaim == null
					|| matchesCustomClaims(whereClaim, initialTokenClaims));
			return result;
		}

	}

	@Data
	public static class SelfIssuedTokenMatcher {

		private Boolean optional;
		private Boolean anyNumberOfApps;
		private Boolean anyApp;
		private ValueMatcher appName;
		private ValueMatcher viaOperation;
		private Map<String, ValueOrCollectionMatcher> whereClaim;

		public boolean matches(SelfIssuedToken stackFrame) {
			if (TRUE.equals(anyNumberOfApps) || TRUE.equals(optional)) {
				return true;
			}

			boolean result = oneNotNull(anyApp, appName, viaOperation, whereClaim);
			result = result && (appName == null || appName.matches(stackFrame.getAudOfIssuer()));
			result = result && (viaOperation == null
					|| viaOperation.matches(stackFrame.getClaims().get(Constants.OPERATION_CLAIM)));
			result = result && (whereClaim == null || matchesCustomClaims(whereClaim, stackFrame.getClaims()));
			return result;

		}

	}

	public static interface PolicyMatcher {
		boolean matches(Object o);
	}

	private static boolean oneNotNull(Object... objects) {
		for (Object o : objects) {
			if (o != null) {
				return true;
			}
		}
		return false;
	}

	private static boolean matchesCustomClaims(Map<String, ValueOrCollectionMatcher> customClaimsMatchers,
			Map<?, ?> claims) {
		boolean result = !customClaimsMatchers.isEmpty();
		for (Entry<String, ValueOrCollectionMatcher> entry : customClaimsMatchers.entrySet()) {
			String claimKey = entry.getKey();
			Object claimValue = claims.get(claimKey);
			result = result && entry.getValue().matches(claimValue);
		}
		return result;
	}
}

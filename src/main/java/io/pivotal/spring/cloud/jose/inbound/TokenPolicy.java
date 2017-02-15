package io.pivotal.spring.cloud.jose.inbound;

import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@ConfigurationProperties("token.policy")
@Data
public class TokenPolicy {

	private List<RuleList> forEachOfTheFollowing;

	@Data
	public static class RuleList {
		private List<Rule> enforceTheFirstMatchingRule;
	}

	@Data
	public static class Rule {
		private boolean anyToken;
		private NestedJwtTokenMatcher tokensThat;
		private NestedJwtTokenMatcher must;
		private boolean mustBeRejected;
	}

	@Data
	public static class NestedJwtTokenMatcher {
		private ValueMatcher haveRequest;
		private IntialTokenMatcher haveInitialToken;
		private List<SelfIssuedTokenMatcher> comeFrom;
		private Map<String, ValueOrCollectionMatcher> haveClaim;
		private NestedJwtTokenMatcher or;
	}

	@Data
	public static class ValueMatcher {
		private Object equalTo;
		private Object matching;
		private List<Object> oneOf;
	}

	@Data
	public static class CollectionMatcher {
		private Object value;
		private List<Object> oneOf;
		private List<Object> allOf;
		private List<Object> only;
	}

	@Data
	public static class ValueOrCollectionMatcher {
		private CollectionMatcher contains;
		private ValueMatcher is;
	}

	@Data
	public static class IntialTokenMatcher {
		private ValueMatcher whereIssuerIs;
		private CollectionMatcher whereScopeContains;
		private CollectionMatcher whereAudienceContains;
		private Map<String, ValueOrCollectionMatcher> whereClaim;
	}

	@Data
	public static class SelfIssuedTokenMatcher {
		private boolean optional;
		private boolean anyNumberOfApps;
		private boolean anyApp;
		private String appName;
		private ValueMatcher viaRequest;
		private Map<String, ValueOrCollectionMatcher> whereClaim;

	}
}

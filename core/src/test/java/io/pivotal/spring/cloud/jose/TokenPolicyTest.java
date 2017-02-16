package io.pivotal.spring.cloud.jose;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import io.pivotal.spring.cloud.jose.inbound.SelfIssuedToken;
import io.pivotal.spring.cloud.jose.inbound.TokenPolicy.NestedJwtTokenMatcher;
import io.pivotal.spring.cloud.jose.inbound.TokenPolicy.Rule;
import io.pivotal.spring.cloud.jose.inbound.TokenPolicy.SelfIssuedTokenMatcher;
import io.pivotal.spring.cloud.jose.inbound.TokenPolicy.ValueMatcher;
import lombok.Getter;

public class TokenPolicyTest {

	private NestedJwtTokenMatcher tokenMatcher;
	private List<SelfIssuedTokenMatcher> comeFrom;
	private List<SelfIssuedToken> callStack;
	private Map<String, Object> initialTokenClaims;

	@Test
	public void anyTokenRuleMatches() {
		Rule rule = new Rule();
		rule.setAnyToken(true);
		assertTrue(rule.matches(new HashMap<>(), new ArrayList<>()));
	}

	@Test
	public void mustFailDoesNotPass() {
		Rule rule = new Rule();
		rule.setMustBeRejected(true);
		assertFalse(rule.passes(new HashMap<>(), new ArrayList<>()));
	}

	@Before
	public void setup() {
		tokenMatcher = new NestedJwtTokenMatcher();
		comeFrom = new ArrayList<>();
		tokenMatcher.setComeFrom(comeFrom);
		callStack = new ArrayList<>();
		initialTokenClaims = Collections.emptyMap();
	}

	@Test
	public void testExactPath() {
		addAppNameMatcher("c");
		addAppNameMatcher("b");
		addAppNameMatcher("a");

		addToCallStack("c", "d");
		addToCallStack("b", "c");
		addToCallStack("a", "b");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("a", "b");
		assertNoMatch();
	}

	@Test
	public void testOptional() {
		addAppNameMatcher("c");
		addAppNameMatcher("b").optional(); // match b or nothing
		addAppNameMatcher("a");

		addToCallStack("c", "d");
		addToCallStack("a", "c");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("b", "c");
		addToCallStack("a", "b");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("d", "c"); // should fail the optional
		addToCallStack("a", "d");
		assertNoMatch();
	}

	@Test
	public void testAnyApp() {
		addAppNameMatcher("c");
		addAnyAppMatcher();
		addAppNameMatcher("a");

		addToCallStack("c", "d");
		addToCallStack("b", "c");
		addToCallStack("a", "b");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("a", "c");
		assertNoMatch();
	}

	@Test
	public void testAnyAppOptional() {
		addAppNameMatcher("c");
		addAnyAppMatcher().optional();
		addAppNameMatcher("a");

		addToCallStack("c", "d");
		addToCallStack("a", "c");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("b", "c");
		addToCallStack("a", "b");
		assertMatch();

		callStack.clear();
		addToCallStack("d", "e");
		addToCallStack("b", "d");
		addToCallStack("a", "b");
		assertNoMatch();
	}

	@Test
	public void testAnyNumberOfApps() {
		addAppNameMatcher("c");
		addAnyNumberOfAppsMatcher();
		addAppNameMatcher("a");

		addToCallStack("c", "d");
		addToCallStack("a", "c");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("b", "c");
		addToCallStack("a", "b");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("b", "c");
		addToCallStack("e", "b");
		addToCallStack("a", "e");
		assertMatch();

		callStack.clear();
		addToCallStack("d", "e");
		addToCallStack("b", "d");
		addToCallStack("a", "b");
		assertNoMatch();
	}

	@Test
	public void testAppNames() {
		addAppNameMatcher("c");
		addAppNamesMatcher("b", "e").operation("foo");
		addAppNameMatcher("a");

		addToCallStack("c", "d");
		new SelfIssuedTokenBuilder("b", "c").claim("op", "foo").addToCallStack(callStack);
		addToCallStack("a", "b");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		new SelfIssuedTokenBuilder("b", "c").claim("op", "foo").addToCallStack(callStack);
		addToCallStack("a", "e");
		assertMatch();

		callStack.clear();
		addToCallStack("c", "d");
		addToCallStack("f", "c");
		addToCallStack("a", "f");
		assertNoMatch();

	}

	@Test
	public void testExactPathAndOperation() {
		addAppNameMatcher("c").operation("baz");
		addAppNameMatcher("b").operation("bar");
		addAppNameMatcher("a").operation("foo");

		new SelfIssuedTokenBuilder("c", "d").claim("op", "baz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("b", "c").claim("op", "bar").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("a", "b").claim("op", "foo").addToCallStack(callStack);
		assertMatch();

		callStack.clear();

		new SelfIssuedTokenBuilder("c", "d").claim("op", "baz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("b", "c").claim("op", "somethingElse").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("a", "b").claim("op", "foo").addToCallStack(callStack);
		assertNoMatch();
	}
	
	@Test
	public void testExactPathAndOperations() {
		addAppNameMatcher("c").operation("baz");
		addAppNameMatcher("b").operations("bar","biz");
		addAppNameMatcher("a").operation("foo");

		new SelfIssuedTokenBuilder("c", "d").claim("op", "baz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("b", "c").claim("op", "bar").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("a", "b").claim("op", "foo").addToCallStack(callStack);
		assertMatch();

		callStack.clear();
		new SelfIssuedTokenBuilder("c", "d").claim("op", "baz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("b", "c").claim("op", "biz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("a", "b").claim("op", "foo").addToCallStack(callStack);
		assertMatch();
		
		callStack.clear();
		new SelfIssuedTokenBuilder("c", "d").claim("op", "baz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("b", "c").claim("op", "buz").addToCallStack(callStack);
		new SelfIssuedTokenBuilder("a", "b").claim("op", "foo").addToCallStack(callStack);
		assertNoMatch();
	}

	private SelfIssuedTokenMatcherBuilder addAnyNumberOfAppsMatcher() {
		SelfIssuedTokenMatcherBuilder builder = new SelfIssuedTokenMatcherBuilder();
		builder.anyNumberOfApps();
		comeFrom.add(builder.build);
		return builder;
	}

	private SelfIssuedTokenMatcherBuilder addAnyAppMatcher() {

		SelfIssuedTokenMatcherBuilder builder = new SelfIssuedTokenMatcherBuilder();
		builder.anyApp();
		comeFrom.add(builder.build);
		return builder;
	}

	private SelfIssuedTokenMatcherBuilder addAppNameMatcher(String appName) {

		SelfIssuedTokenMatcherBuilder builder = new SelfIssuedTokenMatcherBuilder();
		builder.appName(appName);
		comeFrom.add(builder.build);
		return builder;
	}

	private SelfIssuedTokenMatcherBuilder addAppNamesMatcher(Object... appNames) {
		SelfIssuedTokenMatcherBuilder builder = new SelfIssuedTokenMatcherBuilder();
		builder.appNames(appNames);
		comeFrom.add(builder.build);
		return builder;
	}

	@Getter
	private class SelfIssuedTokenMatcherBuilder {

		private final SelfIssuedTokenMatcher build = new SelfIssuedTokenMatcher();

		private SelfIssuedTokenMatcherBuilder appNames(Object... appNames) {
			ValueMatcher nameMatcher = new ValueMatcher();
			nameMatcher.setOneOf(Arrays.asList(appNames));
			build.setAppName(nameMatcher);
			return this;
		}

		public SelfIssuedTokenMatcherBuilder appName(String appName) {
			ValueMatcher nameMatcher = new ValueMatcher();
			nameMatcher.setEqualTo(appName);
			build.setAppName(nameMatcher);
			return this;

		}

		private SelfIssuedTokenMatcherBuilder anyApp() {
			build.setAnyApp(true);
			return this;
		}

		private SelfIssuedTokenMatcherBuilder anyNumberOfApps() {
			build.setAnyNumberOfApps(true);
			return this;
		}

		private SelfIssuedTokenMatcherBuilder optional() {
			build.setOptional(true);
			return this;
		}

		private SelfIssuedTokenMatcherBuilder operation(String op) {
			ValueMatcher opMatcher = new ValueMatcher();
			opMatcher.setEqualTo(op);
			build.setViaOperation(opMatcher);
			return this;
		}

		private SelfIssuedTokenMatcherBuilder operations(Object... ops) {
			ValueMatcher opMatcher = new ValueMatcher();
			opMatcher.setOneOf(Arrays.asList(ops));
			build.setViaOperation(opMatcher);
			return this;
		}

	}

	private void addToCallStack(String audOfIssuer, String... audList) {
		new SelfIssuedTokenBuilder(audOfIssuer, audList).addToCallStack(callStack);
	}

	private static class SelfIssuedTokenBuilder {

		private Map<String, Object> claims = new HashMap<>();
		private String audOfIssuer;

		private SelfIssuedTokenBuilder(String audOfIssuer, String... audList) {
			this.audOfIssuer = audOfIssuer;
			claims.put("aud", Arrays.asList(audList));
		}

		private SelfIssuedTokenBuilder claim(String key, Object value) {
			claims.put(key, value);
			return this;
		}

		private void addToCallStack(List<SelfIssuedToken> callStack) {
			SelfIssuedToken selfIssuedToken = new SelfIssuedToken(audOfIssuer, claims);
			callStack.add(selfIssuedToken);
		}
	}

	private void assertNoMatch() {
		assertFalse(tokenMatcher.matches(initialTokenClaims, callStack));
	}

	private void assertMatch() {
		assertTrue(tokenMatcher.matches(initialTokenClaims, callStack));
	}

}

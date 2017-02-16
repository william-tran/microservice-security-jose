package io.pivotal.spring.cloud.jose.spring;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.pivotal.spring.cloud.jose.inbound.AudienceClaimChecker;
import io.pivotal.spring.cloud.jose.inbound.InitialTokenClaimsExtractor;
import io.pivotal.spring.cloud.jose.inbound.MessageVerifier;
import io.pivotal.spring.cloud.jose.inbound.OperationClaimChecker;
import io.pivotal.spring.cloud.jose.inbound.PublicKeyRegistry;
import io.pivotal.spring.cloud.jose.inbound.ReplayChecker;
import io.pivotal.spring.cloud.jose.inbound.ReplayException;
import io.pivotal.spring.cloud.jose.inbound.SelfIssuedToken;
import io.pivotal.spring.cloud.jose.inbound.TokenPolicy;
import io.pivotal.spring.cloud.jose.inbound.TokenPolicyChecker;
import io.pivotal.spring.cloud.jose.inbound.VerificationException;
import io.pivotal.spring.cloud.jose.inbound.VerifiedMessage;
import io.pivotal.spring.cloud.jose.outbound.Message;
import io.pivotal.spring.cloud.jose.outbound.MessageSigner;
import io.pivotal.spring.cloud.jose.outbound.SignedMessage;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

public class PolicyIntegrationTest {
	
	private static TestApp a;
	private static TestApp b;
	private static TestApp c;
	private static TestApp d;
	private static TestPublicKeyRegistry keyRegistry = new TestPublicKeyRegistry();

	@BeforeClass
	public static void init() {
		
			ConfigurableApplicationContext context = new SpringApplicationBuilder().web(false)
					.properties("spring.aop.proxyTargetClass=true")
					.sources(PolicyIntegrationTest.TestConfig.class).run();
			TokenPolicy policyA = context.getBean("policyA", TokenPolicy.class);
			TokenPolicy policyB = context.getBean("policyB", TokenPolicy.class);
			TokenPolicy policyC = context.getBean("policyC", TokenPolicy.class);
			TokenPolicy policyD = context.getBean("policyD", TokenPolicy.class);
			a = new TestApp("a", policyA, keyRegistry);
			b = new TestApp("b", policyB, keyRegistry);
			c = new TestApp("c", policyC, keyRegistry);
			d = new TestApp("d", policyD, keyRegistry);
			keyRegistry.register(a);
			keyRegistry.register(b);
			keyRegistry.register(c);
			keyRegistry.register(d);
		
	}
	
	@Test
	public void happyPath() {
		SignedMessage signedMessage = a.signMessage("b", "foo", "hello b, time to foo");
		VerifiedMessage verifiedMessage = b.verifyMessage(signedMessage, "foo");
		signedMessage = b.signMessage("c", "bar", "hello c, time to bar", verifiedMessage.getTokenChain());
		verifiedMessage = c.verifyMessage(signedMessage, "bar");
		signedMessage = c.signMessage("d", "baz", "hello d, time to baz", verifiedMessage.getTokenChain());
		verifiedMessage = d.verifyMessage(signedMessage, "baz");
	}
	
	@Test(expected=VerificationException.class)
	public void chainOfCustodyBroken() {
		SignedMessage signedMessage = a.signMessage("b", "foo", "hello b, time to foo");
		VerifiedMessage verifiedMessage = b.verifyMessage(signedMessage, "foo");
		String tokenChainFromA = verifiedMessage.getTokenChain();
		signedMessage = b.signMessage("c", "bar", "hello c, time to bar", tokenChainFromA);
		verifiedMessage = c.verifyMessage(signedMessage, "bar");
		signedMessage = c.signMessage("d", "baz", "hello d, time to baz", tokenChainFromA);
		verifiedMessage = d.verifyMessage(signedMessage, "baz");
	}
	
	@Test
	@Ignore
	public void needsPolicyChange() {
		SignedMessage signedMessage = a.signMessage("b", "foo", "hello b, time to foo");
		VerifiedMessage verifiedMessage = b.verifyMessage(signedMessage, "foo");
		// b is going straight to d
		signedMessage = b.signMessage("d", "baz", "hello d, time to baz", verifiedMessage.getTokenChain());
		verifiedMessage = d.verifyMessage(signedMessage, "baz");
	}
	
	
	@Configuration
	@EnableConfigurationProperties
	static class TestConfig {
		

		@Bean
		@ConfigurationProperties("a.policy")
		public TokenPolicy policyA() {
			return new TokenPolicy();
		}
		
		@Bean
		@ConfigurationProperties("b.policy")
		public TokenPolicy policyB() {
			return new TokenPolicy();
		}
		
		@Bean
		@ConfigurationProperties("c.policy")
		public TokenPolicy policyC() {
			return new TokenPolicy();
		}
		
		@Bean
		@ConfigurationProperties("d.policy")
		public TokenPolicy policyD() {
			return new TokenPolicy();
		}

	}

	@RequiredArgsConstructor
	public static class SimpleAudienceClaimChecker implements AudienceClaimChecker {

		private final String aud;

		@Override
		public void checkAudienceClaim(List<String> claimValue) throws VerificationException {
			if (!claimValue.contains(aud)) {
				throw new VerificationException("aud claim " + claimValue + " does not contain " + aud);
			}
		}
	}

	@RequiredArgsConstructor
	public static class SimpleOperationClaimChecker implements OperationClaimChecker {

		private final String op;

		@Override
		public void checkOperationClaim(String claimValue) throws VerificationException {
			if (!claimValue.equals(op)) {
				throw new VerificationException("op claim " + claimValue + " does not equal " + op);
			}
		}
	}

	public static class NullReplayChecker implements ReplayChecker {

		@Override
		public void recordCallStack(List<SelfIssuedToken> callStack) {
		}

		@Override
		public void checkReplay(List<SelfIssuedToken> callStack) throws ReplayException {
		}

	}

	public static class TestInitialTokenClaimsExtractor implements InitialTokenClaimsExtractor {
		public static final String INITIAL_TOKEN = UUID.randomUUID().toString();

		@Override
		public Map<String, Object> extractVerifiedClaims(String token) {

			if (INITIAL_TOKEN.equals(token)) {
				HashMap<String, Object> claims = new HashMap<>();
				claims.put("sub", "123");
				claims.put("username", "will");
				claims.put("scope", Arrays.asList("app.user", "app.admin"));
				claims.put("iss", "https://uaa.example.com/oauth/token");
				return claims;
			}
			throw new RuntimeException("unrecognized token!!!");
		}

	}

	@Getter
	public static class TestApp {
		private final String appName;
		private final String id;
		private final MessageVerifier messageVerifier;
		private final MessageSigner messageSigner;

		public TestApp(String appName, TokenPolicy tokenPolicy, PublicKeyRegistry keyRegistry) {
			this.appName = appName;
			this.id = UUID.randomUUID().toString();
			this.messageSigner = new MessageSigner(id);
			this.messageVerifier = new MessageVerifier(keyRegistry, new TestInitialTokenClaimsExtractor(),
					new TokenPolicyChecker(tokenPolicy), new NullReplayChecker(),
					new SimpleAudienceClaimChecker(appName));
		}

		public SignedMessage signMessage(String receiver, String operation, String messageString) {
			Message message = Message.builder()
					.initialToken(TestInitialTokenClaimsExtractor.INITIAL_TOKEN)
					.audience(receiver)
					.operation(operation)
					.ttlSeconds(5)
					.contentType("text/plain")
					.body(messageString.getBytes()).build();
			return messageSigner.sign(message);
		}

		public SignedMessage signMessage(String receiver, String operation, String messageString,
				String tokenChain) {
			Message message = Message.builder()
					.parentToken(tokenChain)
					.audience(receiver)
					.operation(operation)
					.ttlSeconds(5)
					.contentType("text/plain")
					.body(messageString.getBytes()).build();
			return messageSigner.sign(message);
		}

		public VerifiedMessage verifyMessage(SignedMessage signedMessage, String expectedOperation) {
			try {
				VerifiedMessage verifiedMessage = messageVerifier.verify(signedMessage,
						new SimpleOperationClaimChecker(expectedOperation));
				System.err.println("app " + appName + " got message body: " + new String(verifiedMessage.getBody()));
				return verifiedMessage;
			} catch (VerificationException e) {
				System.err.println("app " + appName + " got a VerificationException!");
				e.printStackTrace();
				throw e;
			}
		}

	}

	private static class TestPublicKeyRegistry implements PublicKeyRegistry {

		private Map<String, TestEntry> registry = new HashMap<>();

		public void register(TestApp testApp) {
			registry.put(testApp.getId(),
					new TestEntry(testApp.getId(), testApp.getAppName(), testApp.getMessageSigner().getPublicKey()));
		}

		@Override
		public Entry getEntry(String id) {
			return registry.get(id);
		}

		@RequiredArgsConstructor
		@Getter
		private class TestEntry implements Entry {
			private final String id;
			private final String audience;
			private final RSAPublicKey publicKey;

		}
	}

}

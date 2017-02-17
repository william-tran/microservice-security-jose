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

	private static TestApp shop;
	private static TestApp cart;
	private static TestApp inventory;
	private static TestApp suppliers;
	private static TestPublicKeyRegistry keyRegistry = new TestPublicKeyRegistry();

	@BeforeClass
	public static void init() {

		ConfigurableApplicationContext context = new SpringApplicationBuilder().web(false)
				.properties("spring.aop.proxyTargetClass=true")
				.sources(PolicyIntegrationTest.TestConfig.class).run();
		TokenPolicy policyShop = context.getBean("policyShop", TokenPolicy.class);
		TokenPolicy policyCart = context.getBean("policyCart", TokenPolicy.class);
		TokenPolicy policyInventory = context.getBean("policyInventory", TokenPolicy.class);
		TokenPolicy policySuppliers = context.getBean("policySuppliers", TokenPolicy.class);
		shop = new TestApp("shop", policyShop, keyRegistry);
		cart = new TestApp("cart", policyCart, keyRegistry);
		inventory = new TestApp("inventory", policyInventory, keyRegistry);
		suppliers = new TestApp("suppliers", policySuppliers, keyRegistry);
		keyRegistry.register(shop);
		keyRegistry.register(cart);
		keyRegistry.register(inventory);
		keyRegistry.register(suppliers);

	}

	@Test
	public void happyPath() {
		// shop signs a message for cart
		SignedMessage signedMessage = shop.signMessage("cart", "checkout", "hello cart, time to checkout");
		// cart receives and verifies the message
		VerifiedMessage verifiedMessage = cart.verifyMessage(signedMessage, "checkout");
		// cart signs a message for inventory, including the token chain it got from shop
		signedMessage = cart.signMessage("inventory", "commit", "hello inventory, time to move things around",
				verifiedMessage.getTokenChain());
		// inventory receives and verifies the message
		verifiedMessage = inventory.verifyMessage(signedMessage, "commit");
		// inventory signs a message for suppliers, including the token chain it got from cart
		signedMessage = inventory.signMessage("suppliers", "resupply", "hello suppliers, time to order new goods",
				verifiedMessage.getTokenChain());
		// suppliers receives and verifies the message
		verifiedMessage = suppliers.verifyMessage(signedMessage, "resupply");
	}

	@Test(expected = VerificationException.class)
	public void chainOfCustodyBroken() {
		// shop signs a message for cart
		SignedMessage signedMessage = shop.signMessage("cart", "checkout", "hello cart, time to checkout");
		// cart receives and verifies the message
		VerifiedMessage verifiedMessage = cart.verifyMessage(signedMessage, "checkout");
		// save the token chain that cart got from shop to use later
		String tokenChainFromA = verifiedMessage.getTokenChain();
		// cart signs a message for inventory, including the token chain it got from shop
		signedMessage = cart.signMessage("inventory", "commit", "hello inventory, time to move things around", tokenChainFromA);
		// inventory receives and verifies the message
		verifiedMessage = inventory.verifyMessage(signedMessage, "commit");
		// inventory signs a message for suppliers, including a truncated token chain from shop
		signedMessage = inventory.signMessage("suppliers", "resupply", "hello suppliers, time to order new goods", tokenChainFromA);
		// this throws an exception
		verifiedMessage = suppliers.verifyMessage(signedMessage, "resupply");
	}

	@Test
	@Ignore
	public void twoPaths() {
		SignedMessage signedMessage = shop.signMessage("cart", "checkout", "hello cart, time to checkout");
		VerifiedMessage verifiedMessage = cart.verifyMessage(signedMessage, "checkout");
		// cart is going straight to suppliers
		signedMessage = cart.signMessage("suppliers", "resupply", "hello suppliers, time to order new goods", verifiedMessage.getTokenChain());
		verifiedMessage = suppliers.verifyMessage(signedMessage, "resupply");
	}

	@Configuration
	@EnableConfigurationProperties
	static class TestConfig {

		@Bean
		@ConfigurationProperties("shop.policy")
		public TokenPolicy policyShop() {
			return new TokenPolicy();
		}

		@Bean
		@ConfigurationProperties("cart.policy")
		public TokenPolicy policyCart() {
			return new TokenPolicy();
		}

		@Bean
		@ConfigurationProperties("inventory.policy")
		public TokenPolicy policyInventory() {
			return new TokenPolicy();
		}

		@Bean
		@ConfigurationProperties("suppliers.policy")
		public TokenPolicy policySuppliers() {
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
				claims.put("scope", Arrays.asList("shop.user"));
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

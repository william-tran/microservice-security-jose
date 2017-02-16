package io.pivotal.spring.cloud.jose;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.pivotal.spring.cloud.jose.inbound.AudienceClaimChecker;
import io.pivotal.spring.cloud.jose.inbound.IntialTokenClaimsExtrator;
import io.pivotal.spring.cloud.jose.inbound.MessageVerifier;
import io.pivotal.spring.cloud.jose.inbound.OperationClaimChecker;
import io.pivotal.spring.cloud.jose.inbound.PolicyChecker;
import io.pivotal.spring.cloud.jose.inbound.PublicKeyRegistry;
import io.pivotal.spring.cloud.jose.inbound.ReplayChecker;
import io.pivotal.spring.cloud.jose.inbound.SelfIssuedToken;
import io.pivotal.spring.cloud.jose.inbound.VerificationException;
import io.pivotal.spring.cloud.jose.inbound.VerifiedMessage;
import io.pivotal.spring.cloud.jose.outbound.Message;
import io.pivotal.spring.cloud.jose.outbound.MessageSigner;
import io.pivotal.spring.cloud.jose.outbound.SignedMessage;
import lombok.RequiredArgsConstructor;

@RunWith(MockitoJUnitRunner.class)
public class MessageSignAndVerifyIntegrationTest {

	private static final int TTL = 5;
	@Mock
	private ReplayChecker replayChecker;
	@Mock
	private PolicyChecker policyChecker;
	@Mock
	private AudienceClaimChecker audienceClaimChecker;
	@Mock
	private IntialTokenClaimsExtrator intialTokenClaimsExtrator;
	@Mock
	private OperationClaimChecker operationChecker;

	private static List<String> issuers;
	private static Map<String, MessageSigner> signers;
	private PublicKeyRegistry publicKeyRegistry;
	private MessageVerifier verifier;
	private String initialToken;
	private Map<String, Object> initialTokenClaims;
	private byte[] body;
	private String contentType;

	@BeforeClass
	public static void beforeClass() {
		issuers = Arrays.asList("a", "b", "c", "d", "e");
		signers = issuers.stream()
				.collect(Collectors.toMap(Function.identity(), MessageSigner::new));
	}

	@Before
	public void setup() {
		publicKeyRegistry = new TestPublicKeyRegistry(signers);
		verifier = new MessageVerifier(publicKeyRegistry, intialTokenClaimsExtrator, policyChecker, replayChecker,
				audienceClaimChecker);
		initialToken = UUID.randomUUID().toString();
		initialTokenClaims = Collections.singletonMap("sub", UUID.randomUUID().toString());
		when(intialTokenClaimsExtrator.extractVerifiedClaims(initialToken)).thenReturn(initialTokenClaims);

		body = UUID.randomUUID().toString().getBytes();
		contentType = "text/plain";
	}

	@Test
	public void testAtoB() throws Exception {
		doAtoB();
	}

	public SignedAndVerified doAtoB() throws Exception {

		Message aToB = Message.builder()
				.initialToken(initialToken)
				.audience("aud-b")
				.operation("op-b")
				.ttlSeconds(TTL)
				.contentType(contentType)
				.body(body)
				.build();
		SignedMessage signedMessage = signers.get("a").sign(aToB);
		VerifiedMessage verifiedMessage = verifier.verify(signedMessage, operationChecker);

		assertThat(signedMessage.getTokenChainEnvelope().length(), greaterThan(0));
		assertThat(signedMessage.getBody().length(), greaterThan(0));

		verify(operationChecker).checkOperationClaim("op-b");
		verify(audienceClaimChecker).checkAudienceClaim(Collections.singletonList("aud-b"));
		assertThat(verifiedMessage.getContentType(), is(contentType));
		assertThat(verifiedMessage.getBody(), is(body));
		assertThat(verifiedMessage.getInitialTokenClaims(), is(initialTokenClaims));
		assertThat(verifiedMessage.getCallStack().size(), is(1));
		SelfIssuedToken selfIssuedToken = verifiedMessage.getCallStack().get(0);
		assertThat(selfIssuedToken.getAudOfIssuer(), is("aud-a"));
		assertThat(selfIssuedToken.getAudience(), is(Collections.singletonList("aud-b")));

		return new SignedAndVerified(signedMessage, verifiedMessage);
	}

	@Test
	public void testAtoBtoC() throws Exception {
		SignedAndVerified doAtoB = doAtoB();

		Message bToC = Message.builder()
				.parentToken(doAtoB.verifiedMessage.getTokenChain())
				.audience("aud-c")
				.operation("op-c")
				.ttlSeconds(TTL)
				.contentType(contentType)
				.body(body)
				.build();
		SignedMessage signedBToC = signers.get("b").sign(bToC);

		VerifiedMessage verifiedMessage = verifier.verify(signedBToC, operationChecker);
		verify(operationChecker).checkOperationClaim("op-c");
		verify(audienceClaimChecker).checkAudienceClaim(Collections.singletonList("aud-c"));
		assertThat(verifiedMessage.getContentType(), is(contentType));
		assertThat(verifiedMessage.getBody(), is(body));
		assertThat(verifiedMessage.getInitialTokenClaims(), is(initialTokenClaims));
		assertThat(verifiedMessage.getCallStack().size(), is(2));
		SelfIssuedToken depth0 = verifiedMessage.getCallStack().get(0);
		assertThat(depth0.getAudOfIssuer(), is("aud-b"));
		assertThat(depth0.getAudience(), is(Collections.singletonList("aud-c")));
		SelfIssuedToken depth1 = verifiedMessage.getCallStack().get(1);
		assertThat(depth1.getAudOfIssuer(), is("aud-a"));
		assertThat(depth1.getAudience(), is(Collections.singletonList("aud-b")));
	}

	@Test
	public void testBrokenChainOfCustody() throws Exception {
		SignedAndVerified doAtoB = doAtoB();
		Message bToC = Message.builder()
				.parentToken(doAtoB.verifiedMessage.getTokenChain())
				.audience("aud-c")
				.operation("op-c")
				.ttlSeconds(TTL)
				.contentType(contentType)
				.body(body)
				.build();
		SignedMessage signedBToC = signers.get("d").sign(bToC);
		try {
			verifier.verify(signedBToC, operationChecker);
		} catch (VerificationException e) {
			assertThat(e.getMessage(), containsString("chain of custody is inconsistent at depth 0"));
			return;
		}
		Assert.fail();
	}

	@Test
	public void testSignatureVerification() throws Exception {
		SignedAndVerified doAtoB = doAtoB();

		MessageVerifier failingVerifier = new MessageVerifier(new IncorrectPublicKeyRegistry(),
				intialTokenClaimsExtrator, policyChecker, replayChecker, audienceClaimChecker);
		try {
			failingVerifier.verify(doAtoB.signedMessage, operationChecker);
		} catch (VerificationException e) {
			assertThat(e.getMessage(), containsString("signature verification failed"));
			return;
		}
		Assert.fail();
	}

	private class TestPublicKeyRegistry implements PublicKeyRegistry {

		private Map<String, MessageSigner> signers;

		private TestPublicKeyRegistry(Map<String, MessageSigner> signers) {
			this.signers = signers;
		}

		@Override
		public Entry getEntry(String id) {
			MessageSigner messageSigner = signers.get(id);
			return new Entry() {

				@Override
				public RSAPublicKey getPublicKey() {
					return messageSigner.getPublicKey();
				}

				@Override
				public String getId() {
					return id;
				}

				@Override
				public String getAudience() {
					return "aud-" + id;
				}
			};
		}
	}

	private class IncorrectPublicKeyRegistry implements PublicKeyRegistry {

		@Override
		public Entry getEntry(String id) {
			return new Entry() {

				@Override
				public RSAPublicKey getPublicKey() {
					return new MessageSigner("incorrect").getPublicKey();
				}

				@Override
				public String getId() {
					return id;
				}

				@Override
				public String getAudience() {
					return "aud-" + id;
				}
			};
		}
	}

	@RequiredArgsConstructor
	private class SignedAndVerified {
		private final SignedMessage signedMessage;
		private final VerifiedMessage verifiedMessage;
	}
}

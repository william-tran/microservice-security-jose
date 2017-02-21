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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSObject.State;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.pivotal.spring.cloud.jose.Constants;
import io.pivotal.spring.cloud.jose.inbound.PublicKeyRegistry.Entry;
import io.pivotal.spring.cloud.jose.outbound.SignedMessage;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class MessageVerifier {

	private final PublicKeyRegistry keyRegistry;
	private final InitialTokenClaimsExtractor initialTokenClaimsExtractor;
	private final PolicyChecker policyChecker;
	private final ReplayChecker replayChecker;
	private final AudienceClaimChecker audienceClaimChecker;

	public VerifiedMessage verify(SignedMessage message, OperationClaimChecker operationChecker) {

		// parse and verify the JWS Envelope
		JWSObject jwsEnvelope = getJwsEnvelope(message);
		String keyID = jwsEnvelope.getHeader().getKeyID();
		Entry registryEntry = getKeyFromRegistry(keyID);
		JWSVerifier verifier = new RSASSAVerifier(registryEntry.getPublicKey());
		verifyJWSObject(jwsEnvelope, verifier, "JWS envelope for JWT");

		// open the envelope, parse and verify the JWT it contains
		SignedJWT signedJWT = jwsEnvelope.getPayload().toSignedJWT();
		verifyJWSObject(signedJWT, verifier, "JWT depth 0");

		// Check the aud, op, exp claims of the JWT
		JWTClaimsSet jwtClaimsSet = getJWTClaimsSet(signedJWT, 0);
		checkTokenClaims(jwtClaimsSet, operationChecker);

		// Add the JWT to the top of the call stack
		List<SelfIssuedToken> callStack = new ArrayList<>();
		callStack.add(new SelfIssuedToken(registryEntry.getAudience(), jwtClaimsSet.getClaims()));

		// Recurse into the nested JWT, building up the call stack, and ending
		// at the initial token.
		Map<String, Object> initialTokenClaims = parseAndVerifyCallStack(callStack, jwtClaimsSet);

		// Now that we have a verified call stack, we check the consistency of
		// the chain of custody
		checkChainOfCustody(callStack);

		// Ensure the invocation complies with policies
		checkPolicy(initialTokenClaims, callStack);

		// Do this (almost) last because this requires the consumption of the
		// entire message body
		JWSObject jwsBody = parseAndVerifyBody(jwtClaimsSet, message, verifier);

		// Do this last as implementations could require datastore access
		checkReplay(callStack);

		return assembleVerifiedMessage(signedJWT, initialTokenClaims, callStack, jwsBody);
	}
	
	private void checkTokenClaims(JWTClaimsSet jwtClaimsSet, OperationClaimChecker operationChecker) {
		if (jwtClaimsSet.getJWTID() == null) {
			throw new VerificationException("jti cannot be null");
		}
		Date expirationTime = jwtClaimsSet.getExpirationTime();
		if (expirationTime == null) {
			throw new VerificationException("exp must be set");
		} else if (expirationTime.getTime() <= System.currentTimeMillis()) {
			throw new VerificationException("JWT is expired");
		}

		audienceClaimChecker.checkAudienceClaim(jwtClaimsSet.getAudience());

		Object opClaim = jwtClaimsSet.getClaim(Constants.OPERATION_CLAIM);
		if (!(opClaim instanceof String)) {
			throw new VerificationException("op must be a string");
		}
		operationChecker.checkOperationClaim(opClaim.toString());
	}

	private Map<String, Object> parseAndVerifyCallStack(List<SelfIssuedToken> callStack,
			JWTClaimsSet jwtClaimsSet) {
		// recursion ends by returning initial token claims
		Object initialTokenClaim = jwtClaimsSet.getClaim(Constants.INITIAL_TOKEN_CLAIM);
		if (initialTokenClaim != null) {
			return initialTokenClaimsExtractor.extractVerifiedClaims(initialTokenClaim.toString());
		}
		// initial token from the AS might not be included on purpose, end the
		// recursion
		Object parentJwtClaim = jwtClaimsSet.getClaim(Constants.PARENT_JWT_CLAIM);
		if (parentJwtClaim == null) {
			return null;
		}
		// Parse and verify the parent JWT. We use the issuer claim before
		// verifying the JWT, because the issuer claim is used to resolve the
		// verification key. This is fine because we trust the registry enough
		// to prevent unauthorized parties from modifying the registry.
		SignedJWT parentJwt = parseSignedJWT(parentJwtClaim.toString(), callStack.size());
		JWTClaimsSet parentClaimsSet = getJWTClaimsSet(parentJwt, callStack.size());
		Entry keyRegistryEntry = getKeyFromRegistry(parentClaimsSet.getIssuer());
		JWSVerifier verifier = new RSASSAVerifier(keyRegistryEntry.getPublicKey());
		verifyJWSObject(parentJwt, verifier, "JWT depth " + callStack.size());
		// Add the verified claims of the parent JWT to the call stack and
		// recurse.
		callStack.add(new SelfIssuedToken(keyRegistryEntry.getAudience(), parentClaimsSet.getClaims()));
		return parseAndVerifyCallStack(callStack, parentClaimsSet);
	}

	private void checkChainOfCustody(List<SelfIssuedToken> callStack) {
		for (int i = 0; i + 1 < callStack.size(); i++) {
			SelfIssuedToken token = callStack.get(i);
			SelfIssuedToken parent = callStack.get(i + 1);
			if (!parent.getAudience().contains(token.getAudOfIssuer())) {
				throw new VerificationException(
						"chain of custody is inconsistent at depth " + i + ", token issued by aud value "
								+ token.getAudOfIssuer() + " but parent token's aud was " + parent.getAudience());
			}
		}
	}

	private VerifiedMessage assembleVerifiedMessage(SignedJWT tokenChain, Map<String, Object> initialTokenClaims,
			List<SelfIssuedToken> callStack, JWSObject jwsBody) {
		ensureVerified(tokenChain);
		if (jwsBody == null) {
			return new VerifiedMessage(tokenChain.getParsedString(), initialTokenClaims, callStack);
		} else {
			ensureVerified(jwsBody);
			String contentType = jwsBody.getHeader().getContentType();
			byte[] bytes = jwsBody.getPayload().toBytes();
			return new VerifiedMessage(tokenChain.getParsedString(), initialTokenClaims, callStack, contentType, bytes);
		}
	}

	private JWSObject getJwsEnvelope(SignedMessage message) {
		String tokenChainEnvelope = message.getTokenChainEnvelope();
		JWSObject jwsEnvelope;
		try {
			jwsEnvelope = JWSObject.parse(tokenChainEnvelope);
		} catch (ParseException e) {
			throw new VerificationException("JWS envelope for JWT cannot be parsed", e);
		}
		String keyID = jwsEnvelope.getHeader().getKeyID();
		if (keyID == null) {
			throw new VerificationException("JWS envelope for JWT must have kid in header");
		}
		if (!jwsEnvelope.getHeader().getContentType().equals(Constants.JWT_CONTENT_TYPE)) {
			throw new VerificationException("JWS envelope for JWT must have cty header value = 'JWT'");
		}
		return jwsEnvelope;
	}

	private JWTClaimsSet getJWTClaimsSet(SignedJWT signedJWT, int depth) {
		try {
			return signedJWT.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new VerificationException("JWT depth " + depth + " claims could not be parsed", e);
		}
	}

	private JWSObject parseAndVerifyBody(JWTClaimsSet jwtClaimsSet, SignedMessage message, JWSVerifier verifier) {
		JWSObject jwsBody = null;
		if (Boolean.TRUE.equals(jwtClaimsSet.getClaim("bdy"))) {
			try {
				jwsBody = JWSObject.parse(message.getBody());
			} catch (ParseException e) {
				throw new VerificationException("JWS body cannot be parsed", e);
			}
			verifyJWSObject(jwsBody, verifier, "JWS body");
			Object jti = jwsBody.getHeader().getCustomParam(Constants.JWT_ID_CLAIM);
			if (!jwtClaimsSet.getJWTID().equals(jti)) {
				throw new VerificationException("JWT does not belong to given JWS body");
			}
		}
		return jwsBody;
	}

	private void checkReplay(List<SelfIssuedToken> callStack) {
		replayChecker.checkReplay(callStack);
	}

	

	private void checkPolicy(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
		policyChecker.checkPolicy(initialTokenClaims, callStack);
	}

	/**
	 * Safeguard against programming error by calling this before transforming
	 * the JWT or JWS into an object used by the rest of the framework
	 * 
	 * @param jwsObject
	 *            the JWT or JWS
	 */
	private void ensureVerified(JWSObject jwsObject) {
		if (jwsObject.getState() != State.VERIFIED) {
			throw new IllegalArgumentException("JWT or JWS must be verified!");
		}
	}

	private Entry getKeyFromRegistry(String keyId) {
		Entry keyRegistryEntry = keyRegistry.getEntry(keyId);
		if (keyRegistryEntry == null) {
			throw new VerificationException("No entry could be found in key registry for id " + keyId);
		}
		return keyRegistryEntry;
	}

	private SignedJWT parseSignedJWT(String jwt, int depth) {
		try {
			return SignedJWT.parse(jwt);
		} catch (ParseException e) {
			throw new VerificationException("JWT depth " + depth + " could not be parsed", e);
		}
	}

	private void verifyJWSObject(JWSObject jwsEnvelope, JWSVerifier verifier, String objectDescription) {
		try {
			jwsEnvelope.verify(verifier);
		} catch (JOSEException e) {
			throw new VerificationException(objectDescription + " signature verification failed", e);
		}
		if (jwsEnvelope.getState() != State.VERIFIED) {
			throw new VerificationException(objectDescription + " signature verification failed");
		}
	}

}

package io.pivotal.spring.cloud.security.inbound;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSObject.State;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.pivotal.spring.cloud.security.Constants;
import io.pivotal.spring.cloud.security.inbound.PublicKeyRegistry.Entry;
import io.pivotal.spring.cloud.security.outbound.SignedMessage;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class MessageVerifier {

	private final PublicKeyRegistry keyRegistry;
	private final IntialTokenClaimsExtrator intialTokenClaimsExtrator;

	public VerifiedMessage verify(SignedMessage message) {
		String token = message.getToken();

		JWSObject jwsEnvelope;
		try {
			jwsEnvelope = JWSObject.parse(token);
		} catch (ParseException e) {
			throw new VerificationException("JWS envelope for JWT cannot be parsed", e);
		}
		String keyID = jwsEnvelope.getHeader().getKeyID();
		if (keyID == null) {
			throw new VerificationException("JWS envelope for JWT must have kid in header");
		}
		if (!jwsEnvelope.getHeader().getContentType().equals(Constants.JWT_CONTENT_TYPE)) {
			throw new VerificationException("JWS envelope for JWT must have cty header vaue = 'JWT'");
		}

		Entry registryEntry = getKeyFromRegistry(keyID);

		JWSVerifier verifier = new RSASSAVerifier(registryEntry.getPublicKey());

		verifyJWSObject(jwsEnvelope, verifier, "JWS envelope for JWT");
		SignedJWT signedJWT = jwsEnvelope.getPayload().toSignedJWT();
		verifyJWSObject(signedJWT, verifier, "JWT depth 0");
		JWTClaimsSet jwtClaimsSet;
		try {
			jwtClaimsSet = signedJWT.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new VerificationException("JWT depth 0 claims could not be parsed", e);
		}
		
		// verify outer token claims
		
		List<KeyRegistryEntryAndJwtClaimSet> callStack = new ArrayList<>();
		callStack.add(new KeyRegistryEntryAndJwtClaimSet(registryEntry, jwtClaimsSet));
		
		Map<String, Object> initialTokenClaims = parseAndVerifyCallStack(callStack, jwtClaimsSet);
		
		// verify policy
		
		JWSObject jwsBody = null;
		if (Boolean.TRUE.equals(jwtClaimsSet.getClaim("bdy"))) {
			try {
				jwsBody = JWSObject.parse(message.getBody());
			} catch (ParseException e) {
				throw new VerificationException("JWS body cannot be parsed", e);
			}
			verifyJWSObject(jwsBody, verifier, "JWS envelope for JWT");
		}
		
		return assembleVerifiedMessage(initialTokenClaims, callStack, jwsBody);
	}
	
	private VerifiedMessage assembleVerifiedMessage(Map<String,Object> initialTokenClaims, List<KeyRegistryEntryAndJwtClaimSet> callStack, JWSObject jwsBody) {
		
	}

	private Map<String,Object> parseAndVerifyCallStack(List<KeyRegistryEntryAndJwtClaimSet> callStack, JWTClaimsSet jwtClaimsSet) {
		Object initialTokenClaim = jwtClaimsSet.getClaim(Constants.INITIAL_TOKEN_CLAIM);
		if (initialTokenClaim != null) {
			return intialTokenClaimsExtrator.extractVerifiedClaims(initialTokenClaim.toString());
		}
		
		Object parentJwtClaim = jwtClaimsSet.getClaim(Constants.PARENT_JWT_CLAIM);
		if (parentJwtClaim == null) {
			return null;
		}
		SignedJWT parentJwt;
		try {
			parentJwt = SignedJWT.parse(parentJwtClaim.toString());
		} catch (ParseException e) {
			throw new VerificationException("JWT depth " + callStack.size() + " could not be parsed", e);
		}
		JWTClaimsSet parentClaimsSet;
		try {
			parentClaimsSet = parentJwt.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new VerificationException("JWT depth " + callStack.size() + " could not be parsed", e);

		}
		Entry keyRegistryEntry = getKeyFromRegistry(parentClaimsSet.getIssuer());

		JWSVerifier verifier = new RSASSAVerifier(keyRegistryEntry.getPublicKey());

		verifyJWSObject(parentJwt, verifier, "JWS envelope for JWT");
		callStack.add(new KeyRegistryEntryAndJwtClaimSet(keyRegistryEntry, parentClaimsSet));
		return parseAndVerifyCallStack(callStack, parentClaimsSet);
	}

	private Entry getKeyFromRegistry(String keyId) {
		Entry keyRegistryEntry = keyRegistry.getEntry(keyId);
		if (keyRegistryEntry == null) {
			throw new VerificationException("No entry could be found in key registry for id " + keyId);
		}
		return keyRegistryEntry;
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

	@RequiredArgsConstructor
	@Getter
	private static class KeyRegistryEntryAndJwtClaimSet {
		private final Entry keyRegistryEntry;
		private final JWTClaimsSet jwtClaimsSet;
	}

}

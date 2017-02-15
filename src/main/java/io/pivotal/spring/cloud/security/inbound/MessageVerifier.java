package io.pivotal.spring.cloud.security.inbound;

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

import io.pivotal.spring.cloud.security.Constants;
import io.pivotal.spring.cloud.security.inbound.PublicKeyRegistry.Entry;
import io.pivotal.spring.cloud.security.outbound.SignedMessage;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class MessageVerifier {

	private final PublicKeyRegistry keyRegistry;
	private final IntialTokenClaimsExtrator intialTokenClaimsExtrator;
	private final PolicyChecker policyChecker;
	private final ReplayChecker replayChecker;
	private final AudienceClaimChecker audienceClaimChecker;

	public VerifiedMessage verify(SignedMessage message, OperationClaimChecker operationChecker) {
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

		checkTokenClaims(jwtClaimsSet, operationChecker);

		List<SelfIssuedToken> callStack = new ArrayList<>();
		callStack.add(new SelfIssuedToken(registryEntry.getAudience(), jwtClaimsSet.getClaims()));

		Map<String, Object> initialTokenClaims = parseAndVerifyCallStack(callStack, jwtClaimsSet);

		checkPolicy(initialTokenClaims, callStack);

		JWSObject jwsBody = null;
		if (Boolean.TRUE.equals(jwtClaimsSet.getClaim("bdy"))) {
			try {
				jwsBody = JWSObject.parse(message.getBody());
			} catch (ParseException e) {
				throw new VerificationException("JWS body cannot be parsed", e);
			}
			verifyJWSObject(jwsBody, verifier, "JWS envelope for JWT");
			Object jti = jwsBody.getHeader().getCustomParam(Constants.JWT_ID_CLAIM);
			if (!jwtClaimsSet.getJWTID().equals(jti)) {
				throw new VerificationException("JWT does not belong to given JWS body");
			}
		}
		checkReplay(callStack);

		return assembleVerifiedMessage(initialTokenClaims, callStack, jwsBody);
	}

	private void checkReplay(List<SelfIssuedToken> callStack) {
		replayChecker.checkReplay(callStack);
	}

	private void checkTokenClaims(JWTClaimsSet jwtClaimsSet, OperationClaimChecker operationChecker) {
		if (jwtClaimsSet.getJWTID() == null) {
			throw new VerificationException("jti cannot be null");
		}
		Date expirationTime = jwtClaimsSet.getExpirationTime();
		if (expirationTime == null) {
			throw new VerificationException("exp must be set");
		} else if (expirationTime.getTime() <= System.currentTimeMillis()  ) {
			throw new VerificationException("JWT is expired");
		}
		
		audienceClaimChecker.checkAudienceClaim(jwtClaimsSet.getAudience());
		
		Object opClaim = jwtClaimsSet.getClaim(Constants.OPERATION_CLAIM);
		if (!(opClaim instanceof String)) {
			throw new VerificationException("op must be a string");
		}
		operationChecker.checkOperationClaim(opClaim.toString());
		
	}

	private void checkPolicy(Map<String, Object> initialTokenClaims, List<SelfIssuedToken> callStack) {
		policyChecker.checkPolicy(initialTokenClaims, callStack);
	}

	private VerifiedMessage assembleVerifiedMessage(Map<String, Object> initialTokenClaims,
			List<SelfIssuedToken> callStack, JWSObject jwsBody) {
		if (jwsBody == null) {
			return new VerifiedMessage(initialTokenClaims, callStack);
		} else {
			String contentType = jwsBody.getHeader().getContentType();
			byte[] bytes = jwsBody.getPayload().toBytes();
			return new VerifiedMessage(initialTokenClaims, callStack, contentType, bytes);
		}

	}

	private Map<String, Object> parseAndVerifyCallStack(List<SelfIssuedToken> callStack,
			JWTClaimsSet jwtClaimsSet) {
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
		callStack.add(new SelfIssuedToken(keyRegistryEntry.getAudience(), parentClaimsSet.getClaims()));
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


}

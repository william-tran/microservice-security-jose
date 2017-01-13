package io.pivotal.spring.cloud.security.outbound;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map.Entry;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;

public class MessageSigner {

	private static final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
	@Getter
	private final RSAPublicKey publicKey;
	private final JWSSigner signer;
	private final String issuer;

	public MessageSigner(String issuer) {
		this.issuer = issuer;
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(2048);
			KeyPair keypair = keyGenerator.genKeyPair();
			publicKey = (RSAPublicKey) keypair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keypair.getPrivate();
			signer = new RSASSASigner(privateKey);
		} catch (NoSuchAlgorithmException e) {
			throw new SigningException("Cannot create RSA keypair", e);
		}

	}

	public SignedMessage sign(Message message) {
		try {
			message.validate();
		} catch (InvalidMessageException e) {
			throw new SigningException("Cannot sign an invalid message.", e);
		}
		String jti = UUID.randomUUID().toString().replaceAll("-", "");

		String token = getJwsEnvelopedJwt(getSignedJwt(message, jti));
		String body = null;
		if (message.getBody() != null) {
			body = getJws(message, jti);
		}
		return new SignedMessage(token, body);
	}

	private SignedJWT getSignedJwt(Message message, String jti) {
		JWTClaimsSet jwtClaims = getJwtClaims(message, jti);
		JWSHeader jwtHeader = new JWSHeader.Builder(jwsAlgorithm)
				.type(JOSEObjectType.JWT)
				.build();
		SignedJWT signedJWT = new SignedJWT(jwtHeader, jwtClaims);
		try {
			signedJWT.sign(signer);
		} catch (JOSEException e) {
			throw new SigningException("Cannot sign JWT.", e);
		}
		return signedJWT;
	}

	private String getJwsEnvelopedJwt(SignedJWT signedJwt) {
		JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm)
				.type(JOSEObjectType.JOSE)
				.keyID(issuer)
				.contentType("application/jwt")
				.build();
		Payload payload = new Payload(signedJwt);
		JWSObject jws = new JWSObject(jwsHeader, payload);
		try {
			jws.sign(signer);
		} catch (JOSEException e) {
			throw new SigningException("Cannot sign JWS body.", e);
		}
		return jws.serialize();
	}

	private JWTClaimsSet getJwtClaims(Message message, String jti) {
		JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
		claimsBuilder.audience(message.getAudience())
				.issuer(issuer)
				.issueTime(new Date())
				.expirationTime(getExpirationTime(message))
				.jwtID(jti);
		claimsBuilder.claim("req", message.getRequest());
		if (message.getInitialToken() != null) {
			claimsBuilder.claim("ini", message.getInitialToken());
		}
		if (message.getParentToken() != null) {
			claimsBuilder.claim("jwt", message.getInitialToken());
		}
		if (message.getCustomClaims() != null && !message.getCustomClaims().isEmpty()) {
			for (Entry<String, Object> entry : message.getCustomClaims().entrySet()) {
				claimsBuilder.claim(entry.getKey(), entry.getValue());
			}
		}
		if (message.getBody() != null) {
			claimsBuilder.claim("bdy", true);
		}
		return claimsBuilder.build();
	}

	private String getJws(Message message, String jti) {
		JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm)
				.type(JOSEObjectType.JOSE)
				.contentType(message.getContentType())
				.customParam("jti", jti)
				.build();
		Payload payload = new Payload(message.getBody());
		JWSObject jws = new JWSObject(jwsHeader, payload);
		try {
			jws.sign(signer);
		} catch (JOSEException e) {
			throw new SigningException("Cannot sign JWS body.", e);
		}
		return jws.serialize();
	}

	private Date getExpirationTime(Message message) {
		return new Date(System.currentTimeMillis() + message.getTtlSeconds() * 1000);
	}

}

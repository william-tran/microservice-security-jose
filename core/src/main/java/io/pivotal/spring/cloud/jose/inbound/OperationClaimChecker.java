package io.pivotal.spring.cloud.jose.inbound;

public interface OperationClaimChecker {
	
	void checkOperationClaim(String claimValue) throws VerificationException;

}

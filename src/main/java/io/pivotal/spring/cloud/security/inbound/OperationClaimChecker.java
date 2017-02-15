package io.pivotal.spring.cloud.security.inbound;

public interface OperationClaimChecker {
	
	void checkOperationClaim(String claimValue) throws VerificationException;

}

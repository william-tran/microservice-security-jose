package io.pivotal.spring.cloud.security.inbound;

import java.util.List;

public interface AudienceClaimChecker {
	void checkAudienceClaim(List<String> claimValue) throws VerificationException;
}

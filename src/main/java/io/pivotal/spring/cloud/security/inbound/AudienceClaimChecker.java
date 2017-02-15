package io.pivotal.spring.cloud.security.inbound;

import java.util.List;

public interface AudienceClaimChecker {
	/**
	 * Does this service identify itself with one the given aud values?
	 * 
	 * @param claimValue
	 *            the given aud values
	 * @throws VerificationException
	 *             if this service doesn't identify with any of the given aud
	 *             values.
	 */
	void checkAudienceClaim(List<String> claimValue) throws VerificationException;
}

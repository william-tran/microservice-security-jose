package io.pivotal.spring.cloud.security.inbound;

public interface ReplayChecker {
	boolean isReplayed(String jti);
}

package io.pivotal.spring.cloud.security.inbound;

import java.util.List;

public interface ReplayChecker {

	/**
	 * Ensures this callStack cannot be replayed. Usually called after a
	 * successful operation has been performed.
	 * 
	 * @param callStack
	 *            the current callStack
	 */
	void recordCallStack(List<SelfIssuedToken> callStack);

	/**
	 * Examines the call stack to determine if replay has occurred.
	 * Implementations should take into account upstream services that might
	 * legitimately attempt to retry failed operations.
	 * 
	 * @param callStack
	 *            the call stack
	 * @throws ReplayException
	 *             if replay has occurred.
	 */
	void checkReplay(List<SelfIssuedToken> callStack) throws ReplayException;

}

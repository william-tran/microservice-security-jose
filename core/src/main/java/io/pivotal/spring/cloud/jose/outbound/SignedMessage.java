package io.pivotal.spring.cloud.jose.outbound;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class SignedMessage {
	private final String tokenChainEnvelope;
	private final String body;
}

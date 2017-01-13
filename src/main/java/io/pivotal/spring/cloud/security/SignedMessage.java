package io.pivotal.spring.cloud.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class SignedMessage {
	private final String token;
	private final String body;
}

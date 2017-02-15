package io.pivotal.spring.cloud.jose.outbound;

import java.util.List;
import java.util.Map;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

@Builder
@Getter
public class Message {
	private String initialToken;
	private String parentToken;
	@Singular("audience")
	private List<String> audience;
	private String operation;
	private Integer ttlSeconds;
	@Singular("claim")
	private Map<String,Object> customClaims;
	private String contentType;
	private byte[] body;
	
	public void validate() throws InvalidMessageException {
		if (initialToken != null && parentToken != null) {
			throw new InvalidMessageException("Both initialToken and parentToken cannot be set.");
		}
		if (audience == null || audience.isEmpty()) {
			throw new InvalidMessageException("Audience must have at least one value.");
		}
		if (operation == null) {
			throw new InvalidMessageException("Operation must be set.");
		}
		if (body == null && contentType != null || body != null && contentType == null ) {
			throw new InvalidMessageException("Both body and contentType must be null or not null");
		}
	}
}

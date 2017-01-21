package io.pivotal.spring.cloud.security.inbound;

import java.security.interfaces.RSAPublicKey;

public interface PublicKeyRegistry {
	
	public interface Entry {
		String getId();
		String getAudience();
		RSAPublicKey getPublicKey();
	}
	
	Entry getEntry(String id);

}

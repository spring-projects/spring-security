package org.springframework.security.docs.features.authentication.authenticationpasswordstoragescrypt;

import static org.junit.Assert.assertTrue;

import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public class SCryptPasswordEncoderUsage {
	void testSCryptPasswordEncoder() {
		// tag::sCryptPasswordEncoder[]
		// Create an encoder with all the defaults
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
		String result = encoder.encode("myPassword");
		assertTrue(encoder.matches("myPassword", result));
		// end::sCryptPasswordEncoder[]
	}
}

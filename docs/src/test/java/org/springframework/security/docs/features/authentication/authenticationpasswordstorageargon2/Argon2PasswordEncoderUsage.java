package org.springframework.security.docs.features.authentication.authenticationpasswordstorageargon2;

import static org.junit.Assert.assertTrue;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class Argon2PasswordEncoderUsage {
	public void testArgon2PasswordEncoder() {
		// tag::argon2PasswordEncoder[]
		// Create an encoder with all the defaults
		Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
		String result = encoder.encode("myPassword");
		assertTrue(encoder.matches("myPassword", result));
		// end::argon2PasswordEncoder[]
	}
}

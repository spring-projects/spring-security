package org.springframework.security.docs.features.authentication.authenticationpasswordstoragepbkdf2;

import static org.junit.Assert.assertTrue;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

public class Pbkdf2PasswordEncoderUsage {
	void testPbkdf2PasswordEncoder() {
		// tag::pbkdf2PasswordEncoder[]
		// Create an encoder with all the defaults
		Pbkdf2PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
		String result = encoder.encode("myPassword");
		assertTrue(encoder.matches("myPassword", result));
		// end::pbkdf2PasswordEncoder[]
	}
}

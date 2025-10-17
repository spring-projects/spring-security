package org.springframework.security.docs.features.authentication.authenticationpasswordstoragebcrypt;

import static org.junit.Assert.assertTrue;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptPasswordEncoderUsage {
	public void testBCryptPasswordEncoder() {
		// tag::bcryptPasswordEncoder[]
		// Create an encoder with strength 16
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(16);
		String result = encoder.encode("myPassword");
		assertTrue(encoder.matches("myPassword", result));
		// end::bcryptPasswordEncoder[]
	}
}

package org.springframework.security.docs.features.authentication.authenticationpasswordstoragepepper;

import static org.junit.Assert.assertTrue;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.PepperPasswordEncoder;

public class PepperPasswordEncoderUsage {
	public void testPepperPasswordEncoder() {
		// tag::pepperPasswordEncoder[]
		String pepper = getPepperFromSecretManager();
		PasswordEncoder delegate = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		PasswordEncoder encoder = new PepperPasswordEncoder(delegate, pepper);

		String result = encoder.encode("myPassword");
		assertTrue(encoder.matches("myPassword", result));
		// end::pepperPasswordEncoder[]
	}

	private String getPepperFromSecretManager() {
		return "secret-pepper";
	}
}

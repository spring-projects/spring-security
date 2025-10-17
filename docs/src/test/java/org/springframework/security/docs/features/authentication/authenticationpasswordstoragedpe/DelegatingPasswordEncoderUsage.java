package org.springframework.security.docs.features.authentication.authenticationpasswordstoragedpe;

import java.util.HashMap;
import java.util.Map;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public class DelegatingPasswordEncoderUsage {
	PasswordEncoder defaultDelegatingPasswordEncoder() {
		// tag::createDefaultPasswordEncoder[]
		PasswordEncoder passwordEncoder =
				PasswordEncoderFactories.createDelegatingPasswordEncoder();
		// end::createDefaultPasswordEncoder[]
		return passwordEncoder;
	}

	PasswordEncoder customDelegatingPasswordEncoder() {
		// tag::createCustomPasswordEncoder[]
		String idForEncode = "bcrypt";
		Map encoders = new HashMap<>();
		encoders.put(idForEncode, new BCryptPasswordEncoder());
		encoders.put("noop", NoOpPasswordEncoder.getInstance());
		encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_5());
		encoders.put("pbkdf2@SpringSecurity_v5_8", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
		encoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1());
		encoders.put("scrypt@SpringSecurity_v5_8", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
		encoders.put("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2());
		encoders.put("argon2@SpringSecurity_v5_8", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
		encoders.put("sha256", new StandardPasswordEncoder());

		PasswordEncoder passwordEncoder =
			new DelegatingPasswordEncoder(idForEncode, encoders);
		// end::createCustomPasswordEncoder[]
		return passwordEncoder;
	}
}

package org.springframework.security.crypto.password;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class StandardPasswordEncoderTests {

	private StandardPasswordEncoder encoder = new StandardPasswordEncoder("secret");

	@Test
	public void matches() {
		String result = encoder.encode("password");
		assertThat(result).isNotEqualTo("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void matchesLengthChecked() {
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result.substring(0, result.length() - 2))).isFalse();
	}

	@Test
	public void notMatches() {
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

}

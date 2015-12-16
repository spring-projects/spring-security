package org.springframework.security.authentication.encoding;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

/**
 * @author Rob Winch
 */
public class PasswordEncoderUtilsTests {

	@Test
	public void differentLength() {
		assertThat(PasswordEncoderUtils.equals("abc", "a")).isFalse();
		assertThat(PasswordEncoderUtils.equals("a", "abc")).isFalse();
	}

	@Test
	public void equalsNull() {
		assertThat(PasswordEncoderUtils.equals(null, "a")).isFalse();
		assertThat(PasswordEncoderUtils.equals("a", null)).isFalse();
		assertThat(PasswordEncoderUtils.equals(null, null)).isTrue();
	}

	@Test
	public void equalsCaseSensitive() {
		assertThat(PasswordEncoderUtils.equals("aBc", "abc")).isFalse();
	}

	@Test
	public void equalsSuccess() {
		assertThat(PasswordEncoderUtils.equals("abcdef", "abcdef")).isTrue();
	}
}

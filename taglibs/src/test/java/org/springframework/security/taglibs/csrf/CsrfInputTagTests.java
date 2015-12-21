package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Nick Williams
 */
public class CsrfInputTagTests {

	public CsrfInputTag tag;

	@Before
	public void setUp() {
		this.tag = new CsrfInputTag();
	}

	@Test
	public void handleTokenReturnsHiddenInput() {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf",
				"abc123def456ghi789");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();
		assertThat(
				value).withFailMessage("The output is not correct.").isEqualTo("<input type=\"hidden\" name=\"_csrf\" value=\"abc123def456ghi789\" />");
	}

	@Test
	public void handleTokenReturnsHiddenInputDifferentTokenValue() {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "csrfParameter",
				"fooBarBazQux");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();
		assertThat(value).withFailMessage("The output is not correct.").isEqualTo("<input type=\"hidden\" name=\"csrfParameter\" value=\"fooBarBazQux\" />");
	}
}

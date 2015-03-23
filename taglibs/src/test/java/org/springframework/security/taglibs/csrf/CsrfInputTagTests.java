package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import static org.junit.Assert.*;

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

		assertNotNull("The returned value should not be null.", value);
		assertEquals("The output is not correct.",
				"<input type=\"hidden\" name=\"_csrf\" value=\"abc123def456ghi789\" />",
				value);
	}

	@Test
	public void handleTokenReturnsHiddenInputDifferentTokenValue() {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "csrfParameter",
				"fooBarBazQux");

		String value = this.tag.handleToken(token);

		assertNotNull("The returned value should not be null.", value);
		assertEquals(
				"The output is not correct.",
				"<input type=\"hidden\" name=\"csrfParameter\" value=\"fooBarBazQux\" />",
				value);
	}
}

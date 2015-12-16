package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Nick Williams
 */
public class CsrfMetaTagsTagTests {

	public CsrfMetaTagsTag tag;

	@Before
	public void setUp() {
		this.tag = new CsrfMetaTagsTag();
	}

	@Test
	public void handleTokenRendersTags() {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf",
				"abc123def456ghi789");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();
		assertEquals("The output is not correct.",
				"<meta name=\"_csrf_parameter\" content=\"_csrf\" />"
						+ "<meta name=\"_csrf_header\" content=\"X-Csrf-Token\" />"
						+ "<meta name=\"_csrf\" content=\"abc123def456ghi789\" />", value);
	}

	@Test
	public void handleTokenRendersTagsDifferentToken() {
		CsrfToken token = new DefaultCsrfToken("csrfHeader", "csrfParameter",
				"fooBarBazQux");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();
		assertEquals("The output is not correct.",
				"<meta name=\"_csrf_parameter\" content=\"csrfParameter\" />"
						+ "<meta name=\"_csrf_header\" content=\"csrfHeader\" />"
						+ "<meta name=\"_csrf\" content=\"fooBarBazQux\" />", value);
	}
}

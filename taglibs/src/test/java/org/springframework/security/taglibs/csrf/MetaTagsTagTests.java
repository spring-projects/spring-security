package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import static org.junit.Assert.*;

/**
 * @author Nick Williams
 */
public class MetaTagsTagTests {

    public MetaTagsTag tag;

    @Before
    public void setUp() {
        this.tag = new MetaTagsTag();
    }

    @Test
    public void testHandleToken01() {
        CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf", "abc123def456ghi789");

        String value = this.tag.handleToken(token);

        assertNotNull("The returned value should not be null.", value);
        assertEquals("The output is not correct.",
                "<meta name=\"_csrf_parameter\" content=\"_csrf\" />\n" +
                        "        <meta name=\"_csrf_header\" content=\"X-Csrf-Token\" />\n" +
                        "        <meta name=\"_csrf\" content=\"abc123def456ghi789\" />\n",
                value);
    }

    @Test
    public void testHandleToken02() {
        CsrfToken token = new DefaultCsrfToken("csrfHeader", "csrfParameter", "fooBarBazQux");

        String value = this.tag.handleToken(token);

        assertNotNull("The returned value should not be null.", value);
        assertEquals("The output is not correct.",
                "<meta name=\"_csrf_parameter\" content=\"csrfParameter\" />\n" +
                        "        <meta name=\"_csrf_header\" content=\"csrfHeader\" />\n" +
                        "        <meta name=\"_csrf\" content=\"fooBarBazQux\" />\n",
                value);
    }
}

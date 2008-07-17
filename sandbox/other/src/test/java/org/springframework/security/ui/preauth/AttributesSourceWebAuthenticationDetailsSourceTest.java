/**
 * 
 */
package org.springframework.security.ui.preauth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Valery Tydykov
 * 
 */
public class AttributesSourceWebAuthenticationDetailsSourceTest extends TestCase {

    AttributesSourceWebAuthenticationDetailsSource authenticationDetailsSource;

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        authenticationDetailsSource = new AttributesSourceWebAuthenticationDetailsSource();
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        authenticationDetailsSource = null;
    }

    /**
     * Test method for
     * {@link org.springframework.security.ui.preauth.AttributesSourceWebAuthenticationDetailsSource#buildDetails(java.lang.Object)}.
     */
    public final void testBuildDetailsObjectHeader() {
        authenticationDetailsSource.setClazz(AuthenticationDetailsImpl.class);

        String key1 = "key1";
        String value1 = "value1";
        String key2 = "key2";
        String value2 = "value2";
        String key3 = "key3";
        String value3 = "value3";

        {
            HeaderAttributesSource attributesSource = new HeaderAttributesSource();

            {
                List keys = new ArrayList();
                keys.add(key1);
                keys.add(key2);
                keys.add(key3);
                attributesSource.setKeys(keys);
            }

            authenticationDetailsSource.setAttributesSource(attributesSource);
        }

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(key1, value1);
        request.addHeader(key2, value2);
        request.addHeader(key3, value3);
        AuthenticationDetailsImpl authenticationDetails = (AuthenticationDetailsImpl) authenticationDetailsSource
            .buildDetails(request);

        assertEquals(value1, authenticationDetails.getAttributes().get(key1));
        assertEquals(value2, authenticationDetails.getAttributes().get(key2));
        assertEquals(value3, authenticationDetails.getAttributes().get(key3));
    }

    public final void testBuildDetailsObjectCookie() {
        authenticationDetailsSource.setClazz(AuthenticationDetailsImpl.class);

        String key1 = "key1";
        String value1 = "value1";
        String key2 = "key2";
        String value2 = "value2";
        String key3 = "key3";
        String value3 = "value3";

        {
            CookieAttributesSource attributesSource = new CookieAttributesSource();

            {
                List keys = new ArrayList();
                keys.add(key1);
                keys.add(key2);
                keys.add(key3);
                attributesSource.setKeys(keys);
            }

            authenticationDetailsSource.setAttributesSource(attributesSource);
        }

        MockHttpServletRequest request = new MockHttpServletRequest();

        {
            Cookie[] cookies = new Cookie[] { new Cookie(key1, value1), new Cookie(key2, value2),
                    new Cookie(key3, value3) };
            request.setCookies(cookies);
        }

        AuthenticationDetailsImpl authenticationDetails = (AuthenticationDetailsImpl) authenticationDetailsSource
            .buildDetails(request);

        assertEquals(value1, authenticationDetails.getAttributes().get(key1));
        assertEquals(value2, authenticationDetails.getAttributes().get(key2));
        assertEquals(value3, authenticationDetails.getAttributes().get(key3));
    }

    public final void testBuildDetailsObjectProperty() {
        authenticationDetailsSource.setClazz(AuthenticationDetailsImpl.class);

        String key1 = "key1";
        String value1 = "value1";
        String key2 = "key2";
        String value2 = "value2";
        String key3 = "key3";
        String value3 = "value3";

        {
            PropertyAttributesSource attributesSource = new PropertyAttributesSource();

            {
                Map attributes = new HashMap();
                attributes.put(key1, value1);
                attributes.put(key2, value2);
                attributes.put(key3, value3);
                attributesSource.setAttributes(attributes);
            }

            authenticationDetailsSource.setAttributesSource(attributesSource);
        }

        MockHttpServletRequest request = new MockHttpServletRequest();

        AuthenticationDetailsImpl authenticationDetails = (AuthenticationDetailsImpl) authenticationDetailsSource
            .buildDetails(request);

        assertEquals(value1, authenticationDetails.getAttributes().get(key1));
        assertEquals(value2, authenticationDetails.getAttributes().get(key2));
        assertEquals(value3, authenticationDetails.getAttributes().get(key3));
    }

    public final void testSetUsername() {
        try {
            authenticationDetailsSource.setAttributesSource(null);
            fail("exception expected");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }

    public final void testAfterPropertiesSet() {
        try {
            authenticationDetailsSource.afterPropertiesSet();
            fail("expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }
}

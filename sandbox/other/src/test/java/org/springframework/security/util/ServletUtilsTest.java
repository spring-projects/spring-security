/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Valery Tydykov
 * 
 */
public class ServletUtilsTest extends TestCase {

    /**
     * Test method for
     * {@link org.springframework.security.util.ServletUtils#extractHeaderValues(javax.servlet.http.HttpServletRequest, java.util.List)}.
     */
    public final void testExtractHeaderValues() {
        List keys = new ArrayList();
        String key1 = "key1";
        keys.add(key1);
        String key2 = "key2";
        keys.add(key2);
        String key3 = "key3";
        keys.add(key3);

        MockHttpServletRequest request = new MockHttpServletRequest();
        String value1 = "value1";
        request.addHeader(key1, value1);
        String value2 = "value2";
        request.addHeader(key2, value2);

        Map values = ServletUtils.extractHeaderValues(request, keys);

        assertEquals(value1, values.get(key1));
        assertEquals(value2, values.get(key2));
        assertEquals(null, values.get(key3));
    }

    /**
     * Test method for
     * {@link org.springframework.security.util.ServletUtils#extractCookiesValues(javax.servlet.http.HttpServletRequest, java.util.List)}.
     */
    public final void testExtractCookiesValues() {
        List keys = new ArrayList();
        String key1 = "key1";
        keys.add(key1);
        String key2 = "key2";
        keys.add(key2);
        String key3 = "key3";
        keys.add(key3);

        MockHttpServletRequest request = new MockHttpServletRequest();
        String value1 = "value1";
        String value2 = "value2";

        {
            Cookie[] cookies = new Cookie[] { new Cookie(key1, value1), new Cookie(key2, value2) };
            request.setCookies(cookies);
        }

        Map values = ServletUtils.extractCookiesValues(request, keys);

        assertEquals(value1, values.get(key1));
        assertEquals(value2, values.get(key2));
        assertEquals(null, values.get(key3));
    }

    /**
     * Test method for
     * {@link org.springframework.security.util.ServletUtils#findCookieValue(javax.servlet.http.HttpServletRequest, java.lang.String)}.
     */
    public final void testFindCookieValue() {
        List keys = new ArrayList();
        String key1 = "key1";
        keys.add(key1);

        MockHttpServletRequest request = new MockHttpServletRequest();
        String valueExpected = "value1";
        {
            Cookie[] cookies = new Cookie[] { new Cookie(key1, valueExpected), };
            request.setCookies(cookies);
        }

        String value = ServletUtils.findCookieValue(request, key1);

        assertEquals(valueExpected, value);
    }

    public final void testFindCookieValueNotFound() {
        List keys = new ArrayList();
        String key1 = "key1";
        keys.add(key1);

        MockHttpServletRequest request = new MockHttpServletRequest();
        {
            Cookie[] cookies = new Cookie[0];
            request.setCookies(cookies);
        }

        String value = ServletUtils.findCookieValue(request, key1);

        assertEquals(null, value);
    }
}

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

import java.util.List;

import junit.framework.TestCase;

/**
 * @author Valery Tydykov
 * 
 */
public class StringUtilsTest extends TestCase {

    /**
     * Test method for
     * {@link org.springframework.security.util.StringUtils#tokenizeString(java.lang.String, java.lang.String)}.
     */
    public final void testTokenizeString() {
        {
            String source = "one,two,three";
            String separator = ",";
            List result = StringUtils.tokenizeString(source, separator);

            assertTrue(result.contains("one"));
            assertTrue(result.contains("two"));
            assertTrue(result.contains("three"));
        }
        {
            String source = null;
            String separator = null;
            List result = StringUtils.tokenizeString(source, separator);

            assertTrue(result.isEmpty());
        }
        {
            String source = "one,two,three";
            String separator = "noMatch";
            List result = StringUtils.tokenizeString(source, separator);

            assertTrue(result.contains(source));
        }
    }

    /**
     * Test method for
     * {@link org.springframework.security.util.StringUtils#notNull(java.lang.Object)}.
     */
    public final void testNotNull() {
        {
            Object object = null;
            String result = StringUtils.notNull(object);
            assertEquals("", result);
        }
        {
            Object object = "myString";
            String result = StringUtils.notNull(object);
            assertEquals(object, result);
        }
        {
            String expected = "12345";
            Object object = new Integer(expected);
            String result = StringUtils.notNull(object);
            assertEquals(expected, result);
        }
    }
}

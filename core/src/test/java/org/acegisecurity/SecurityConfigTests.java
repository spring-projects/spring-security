/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity;

import junit.framework.TestCase;


/**
 * Tests {@link SecurityConfig}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityConfigTests extends TestCase {
    //~ Constructors ===========================================================

    public SecurityConfigTests() {
        super();
    }

    public SecurityConfigTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SecurityConfigTests.class);
    }

    public void testHashCode() {
        SecurityConfig config = new SecurityConfig("TEST");
        assertEquals("TEST".hashCode(), config.hashCode());
    }

    public void testNoArgsConstructor() {
        try {
            new SecurityConfig();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testObjectEquals() throws Exception {
        SecurityConfig security1 = new SecurityConfig("TEST");
        SecurityConfig security2 = new SecurityConfig("TEST");
        assertEquals(security1, security2);

        String securityString1 = "TEST";
        assertEquals(security1, securityString1);

        String securityString2 = "NOT_EQUAL";
        assertTrue(!security1.equals(securityString2));

        SecurityConfig security3 = new SecurityConfig("NOT_EQUAL");
        assertTrue(!security1.equals(security3));

        MockConfigAttribute mock1 = new MockConfigAttribute("TEST");
        assertEquals(security1, mock1);

        MockConfigAttribute mock2 = new MockConfigAttribute("NOT_EQUAL");
        assertTrue(!security1.equals(mock2));

        Integer int1 = new Integer(987);
        assertTrue(!security1.equals(int1));
    }

    public void testToString() {
        SecurityConfig config = new SecurityConfig("TEST");
        assertEquals("TEST", config.toString());
    }

    //~ Inner Classes ==========================================================

    private class MockConfigAttribute implements ConfigAttribute {
        private String attribute;

        public MockConfigAttribute(String configuration) {
            this.attribute = configuration;
        }

        private MockConfigAttribute() {
            super();
        }

        public String getAttribute() {
            return this.attribute;
        }
    }
}

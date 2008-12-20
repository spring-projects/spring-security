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

package org.springframework.security;

import junit.framework.Assert;

import org.junit.Test;


/**
 * Tests {@link SecurityConfig}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityConfigTests {

    //~ Methods ========================================================================================================

    @Test
    public void testHashCode() {
        SecurityConfig config = new SecurityConfig("TEST");
        Assert.assertEquals("TEST".hashCode(), config.hashCode());
    }
    
    @Test(expected=IllegalArgumentException.class)
    public void testCannotConstructWithNullAttribute() {
           new SecurityConfig(null); // SEC-727
    }

    @Test(expected=IllegalArgumentException.class)
    public void testCannotConstructWithEmptyAttribute() {
           new SecurityConfig(""); // SEC-727
    }

    @Test(expected=NoSuchMethodException.class)
    public void testNoArgConstructorDoesntExist() throws Exception {
        SecurityConfig.class.getDeclaredConstructor((Class[]) null);
    }

    @Test
    public void testObjectEquals() throws Exception {
        SecurityConfig security1 = new SecurityConfig("TEST");
        SecurityConfig security2 = new SecurityConfig("TEST");
        Assert.assertEquals(security1, security2);

        // SEC-311: Must observe symmetry requirement of Object.equals(Object) contract
        String securityString1 = "TEST";
        Assert.assertNotSame(security1, securityString1);

        String securityString2 = "NOT_EQUAL";
        Assert.assertTrue(!security1.equals(securityString2));

        SecurityConfig security3 = new SecurityConfig("NOT_EQUAL");
        Assert.assertTrue(!security1.equals(security3));

        MockConfigAttribute mock1 = new MockConfigAttribute("TEST");
        Assert.assertEquals(security1, mock1);

        MockConfigAttribute mock2 = new MockConfigAttribute("NOT_EQUAL");
        Assert.assertTrue(!security1.equals(mock2));

        Integer int1 = new Integer(987);
        Assert.assertTrue(!security1.equals(int1));
    }

    @Test
    public void testToString() {
        SecurityConfig config = new SecurityConfig("TEST");
        Assert.assertEquals("TEST", config.toString());
    }
    
    //~ Inner Classes ==================================================================================================

    private class MockConfigAttribute implements ConfigAttribute {
        private String attribute;

        public MockConfigAttribute(String configuration) {
            this.attribute = configuration;
        }

        public String getAttribute() {
            return this.attribute;
        }
    }
}

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

import static org.junit.Assert.*;

import org.junit.Test;


/**
 * Tests {@link GrantedAuthorityImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GrantedAuthorityImplTests {

    @Test
    public void equalsBehavesAsExpected() throws Exception {
        GrantedAuthorityImpl auth1 = new GrantedAuthorityImpl("TEST");
        GrantedAuthorityImpl auth2 = new GrantedAuthorityImpl("TEST");
        assertEquals(auth1, auth2);

        String authString1 = "TEST";
        assertEquals(auth1, authString1);

        String authString2 = "NOT_EQUAL";
        assertTrue(!auth1.equals(authString2));

        GrantedAuthorityImpl auth3 = new GrantedAuthorityImpl("NOT_EQUAL");
        assertTrue(!auth1.equals(auth3));

        MockGrantedAuthority mock1 = new MockGrantedAuthority("TEST");
        assertEquals(auth1, mock1);

        MockGrantedAuthority mock2 = new MockGrantedAuthority("NOT_EQUAL");
        assertTrue(!auth1.equals(mock2));

        Integer int1 = new Integer(222);
        assertTrue(!auth1.equals(int1));
    }

    @Test
    public void toStringReturnsAuthorityValue() {
        GrantedAuthorityImpl auth = new GrantedAuthorityImpl("TEST");
        assertEquals("TEST", auth.toString());
    }

    @Test
    public void compareToGrantedAuthorityWithSameValueReturns0() {
        assertEquals(0, new GrantedAuthorityImpl("TEST").compareTo(new MockGrantedAuthority("TEST")));
    }

    @Test
    public void compareToNullReturnsNegativeOne() {
        assertEquals(-1, new GrantedAuthorityImpl("TEST").compareTo(null));
    }

    /* SEC-899 */
    @Test
    public void compareToHandlesCustomAuthorityWhichReturnsNullFromGetAuthority() {
        assertEquals(-1, new GrantedAuthorityImpl("TEST").compareTo(new MockGrantedAuthority()));
    }

    //~ Inner Classes ==================================================================================================

    private class MockGrantedAuthority implements GrantedAuthority {
        private String role;

        public MockGrantedAuthority() {
        }

        public MockGrantedAuthority(String role) {
            this.role = role;
        }

        public int compareTo(GrantedAuthority o) {
            throw new UnsupportedOperationException();
        }

        public String getAuthority() {
            return this.role;
        }
    }
}

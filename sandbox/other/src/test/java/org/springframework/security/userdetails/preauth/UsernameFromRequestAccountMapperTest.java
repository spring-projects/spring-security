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
package org.springframework.security.userdetails.preauth;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.providers.TestingAuthenticationToken;

/**
 * @author Valery Tydykov
 * 
 */
public class UsernameFromRequestAccountMapperTest extends TestCase {

    UsernameFromRequestAccountMapper mapper;

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        mapper = new UsernameFromRequestAccountMapper();
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        mapper = null;
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.preauth.UsernameFromRequestAccountMapper#map(org.springframework.security.Authentication)}.
     */
    public final void testNormalOperation() {
        String usernameExpected = "username1";
        Authentication authenticationRequest = new TestingAuthenticationToken(usernameExpected,
            "password1", null);
        String username = mapper.map(authenticationRequest);

        assertEquals(usernameExpected, username);
    }
}

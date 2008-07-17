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
package org.springframework.security.userdetails.ldap;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;

/**
 * @author Valery Tydykov
 * 
 */
public class UsernameFromPropertyAccountMapperTest extends TestCase {

    UsernameFromPropertyAccountMapper mapper;

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        mapper = new UsernameFromPropertyAccountMapper();
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
     * {@link org.springframework.security.userdetails.ldap.UsernameFromPropertyAccountMapper#map(org.springframework.security.userdetails.UserDetails)}.
     */
    public final void testNormalOperation() {
        String usernameExpected = "username1";
        UserDetails user = new User(usernameExpected, "password1", false, new GrantedAuthority[0]);
        mapper.setUsername(usernameExpected);
        String username = mapper.map(user);

        assertEquals(usernameExpected, username);
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.UsernameFromPropertyAccountMapper#setUsername(java.lang.String)}.
     */
    public final void testSetUserName() {
        try {
            mapper.setUsername(null);
            fail("exception expected");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.UsernameFromPropertyAccountMapper#afterPropertiesSet()}.
     */
    public final void testAfterPropertiesSet() {
        try {
            mapper.afterPropertiesSet();
            fail("expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }
}

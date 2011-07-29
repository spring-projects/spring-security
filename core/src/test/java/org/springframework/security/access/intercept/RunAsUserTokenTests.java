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

package org.springframework.security.access.intercept;

import junit.framework.TestCase;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;


/**
 * Tests {@link RunAsUserToken}.
 *
 * @author Ben Alex
 */
public class RunAsUserTokenTests extends TestCase {

    public void testAuthenticationSetting() {
        RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), UsernamePasswordAuthenticationToken.class);
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());
    }

    public void testGetters() {
        RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), UsernamePasswordAuthenticationToken.class);
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("my_password".hashCode(), token.getKeyHash());
        assertEquals(UsernamePasswordAuthenticationToken.class, token.getOriginalAuthentication());
    }

    public void testNoArgConstructorDoesntExist() {
        Class<RunAsUserToken> clazz = RunAsUserToken.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }

    public void testToString() {
        RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), UsernamePasswordAuthenticationToken.class);
        assertTrue(token.toString().lastIndexOf("Original Class: "+UsernamePasswordAuthenticationToken.class.getName().toString()) != -1);
    }

    // SEC-1792
    public void testToStringNullOriginalAuthentication() {
        RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), null);
        assertTrue(token.toString().lastIndexOf("Original Class: null") != -1);
    }
}

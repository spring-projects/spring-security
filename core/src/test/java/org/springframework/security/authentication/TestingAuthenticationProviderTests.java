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

package org.springframework.security.authentication;

import junit.framework.TestCase;

import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests {@link TestingAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TestingAuthenticationProviderTests extends TestCase {

    public void testAuthenticates() {
        TestingAuthenticationProvider provider = new TestingAuthenticationProvider();
        TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password","ROLE_ONE","ROLE_TWO");
        Authentication result = provider.authenticate(token);

        assertTrue(result instanceof TestingAuthenticationToken);

        TestingAuthenticationToken castResult = (TestingAuthenticationToken) result;
        assertEquals("Test", castResult.getPrincipal());
        assertEquals("Password", castResult.getCredentials());
        assertTrue(AuthorityUtils.authorityListToSet(castResult.getAuthorities()).contains("ROLE_ONE"));
        assertTrue(AuthorityUtils.authorityListToSet(castResult.getAuthorities()).contains("ROLE_TWO"));
    }

    public void testSupports() {
        TestingAuthenticationProvider provider = new TestingAuthenticationProvider();
        assertTrue(provider.supports(TestingAuthenticationToken.class));
        assertTrue(!provider.supports(String.class));
    }
}

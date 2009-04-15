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

package org.springframework.security.authentication.rcp;

import junit.framework.TestCase;


import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.rcp.RemoteAuthenticationException;
import org.springframework.security.authentication.rcp.RemoteAuthenticationManager;
import org.springframework.security.authentication.rcp.RemoteAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;


/**
 * Tests {@link RemoteAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RemoteAuthenticationProviderTests extends TestCase {
    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RemoteAuthenticationProviderTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testExceptionsGetPassedBackToCaller() {
        RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
        provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(false));

        try {
            provider.authenticate(new UsernamePasswordAuthenticationToken("rod", "password"));
            fail("Should have thrown RemoteAuthenticationException");
        } catch (RemoteAuthenticationException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
        provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(true));
        assertNotNull(provider.getRemoteAuthenticationManager());
    }

    public void testStartupChecksAuthenticationManagerSet()
        throws Exception {
        RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(true));
        provider.afterPropertiesSet();
        assertTrue(true);
    }

    public void testSuccessfulAuthenticationCreatesObject() {
        RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
        provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(true));

        Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("rod", "password"));
        assertEquals("rod", result.getPrincipal());
        assertEquals("password", result.getCredentials());
        assertEquals("foo", result.getAuthorities().get(0).getAuthority());
    }

    public void testSupports() {
        RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    //~ Inner Classes ==================================================================================================

    private class MockRemoteAuthenticationManager implements RemoteAuthenticationManager {
        private boolean grantAccess;

        public MockRemoteAuthenticationManager(boolean grantAccess) {
            this.grantAccess = grantAccess;
        }

        public GrantedAuthority[] attemptAuthentication(String username, String password)
            throws RemoteAuthenticationException {
            if (grantAccess) {
                return new GrantedAuthority[] {new GrantedAuthorityImpl("foo")};
            } else {
                throw new RemoteAuthenticationException("as requested");
            }
        }
    }
}

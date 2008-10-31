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

package org.springframework.security.providers.rcp;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.MockAuthenticationManager;


/**
 * Tests {@link RemoteAuthenticationManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RemoteAuthenticationManagerImplTests extends TestCase {
    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RemoteAuthenticationManagerImplTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testFailedAuthenticationReturnsRemoteAuthenticationException() {
        RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();
        manager.setAuthenticationManager(new MockAuthenticationManager(false));

        try {
            manager.attemptAuthentication("rod", "password");
            fail("Should have thrown RemoteAuthenticationException");
        } catch (RemoteAuthenticationException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();
        manager.setAuthenticationManager(new MockAuthenticationManager(true));
        assertNotNull(manager.getAuthenticationManager());
    }

    public void testStartupChecksAuthenticationManagerSet() throws Exception {
        RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();

        try {
            manager.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        manager.setAuthenticationManager(new MockAuthenticationManager(true));
        manager.afterPropertiesSet();
        assertTrue(true);
    }

    public void testSuccessfulAuthentication() {
        RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();
        manager.setAuthenticationManager(new MockAuthenticationManager(true));

        GrantedAuthority[] result = manager.attemptAuthentication("rod", "password");
        assertTrue(true);
    }
}

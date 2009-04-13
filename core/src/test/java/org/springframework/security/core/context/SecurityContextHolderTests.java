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

package org.springframework.security.core.context;

import junit.framework.TestCase;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

/**
 * Tests {@link SecurityContextHolder}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityContextHolderTests extends TestCase {

    //~ Methods ========================================================================================================

    public final void setUp() throws Exception {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    public void testContextHolderGetterSetterClearer() {
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(new UsernamePasswordAuthenticationToken("Foobar", "pass"));
        SecurityContextHolder.setContext(sc);
        assertEquals(sc, SecurityContextHolder.getContext());
        SecurityContextHolder.clearContext();
        assertNotSame(sc, SecurityContextHolder.getContext());
        SecurityContextHolder.clearContext();
    }

    public void testNeverReturnsNull() {
        assertNotNull(SecurityContextHolder.getContext());
        SecurityContextHolder.clearContext();
    }

    public void testRejectsNulls() {
        try {
            SecurityContextHolder.setContext(null);
            fail("Should have rejected null");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
}

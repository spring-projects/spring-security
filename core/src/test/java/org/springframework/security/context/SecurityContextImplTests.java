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

package org.springframework.security.context;

import junit.framework.TestCase;

import org.springframework.security.Authentication;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link SecurityContextImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityContextImplTests extends TestCase {
    //~ Constructors ===================================================================================================

    public SecurityContextImplTests() {
        super();
    }

    public SecurityContextImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SecurityContextImplTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testEmptyObjectsAreEquals() {
        SecurityContextImpl obj1 = new SecurityContextImpl();
        SecurityContextImpl obj2 = new SecurityContextImpl();
        assertTrue(obj1.equals(obj2));
    }

    public void testSecurityContextCorrectOperation() {
        SecurityContext context = new SecurityContextImpl();
        Authentication auth = new UsernamePasswordAuthenticationToken("rod", "koala");
        context.setAuthentication(auth);
        assertEquals(auth, context.getAuthentication());
        assertTrue(context.toString().lastIndexOf("rod") != -1);
    }
}

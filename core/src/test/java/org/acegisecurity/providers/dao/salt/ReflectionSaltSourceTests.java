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

package org.acegisecurity.providers.dao.salt;

import junit.framework.TestCase;

import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;


/**
 * Tests {@link ReflectionSaltSource}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ReflectionSaltSourceTests extends TestCase {
    //~ Constructors ===================================================================================================

    public ReflectionSaltSourceTests() {
        super();
    }

    public ReflectionSaltSourceTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ReflectionSaltSourceTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsMissingUserPropertyToUse() throws Exception {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();

        try {
            saltSource.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A userPropertyToUse must be set", expected.getMessage());
        }
    }

    public void testExceptionWhenInvalidPropertyRequested() {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse("getDoesNotExist");

        UserDetails user = new User("scott", "wombat", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("HOLDER")});

        try {
            saltSource.getSalt(user);
            fail("Should have thrown AuthenticationServiceException");
        } catch (AuthenticationServiceException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse("getUsername");
        assertEquals("getUsername", saltSource.getUserPropertyToUse());
    }

    public void testNormalOperation() throws Exception {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse("getUsername");
        saltSource.afterPropertiesSet();

        UserDetails user = new User("scott", "wombat", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("HOLDER")});
        assertEquals("scott", saltSource.getSalt(user));
    }
}

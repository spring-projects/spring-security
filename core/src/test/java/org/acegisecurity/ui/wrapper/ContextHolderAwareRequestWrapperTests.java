/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.wrapper;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import net.sf.acegisecurity.providers.dao.User;


/**
 * Tests {@link ContextHolderAwareRequestWrapper}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextHolderAwareRequestWrapperTests extends TestCase {
    //~ Constructors ===========================================================

    public ContextHolderAwareRequestWrapperTests() {
        super();
    }

    public ContextHolderAwareRequestWrapperTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ContextHolderAwareRequestWrapperTests.class);
    }

    public void testCorrectOperationWithStringBasedPrincipal()
        throws Exception {
        SecureContext sc = new SecureContextImpl();
        Authentication auth = new TestingAuthenticationToken("marissa",
                "koala",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FOO")});
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        ContextHolderAwareRequestWrapper wrapper = new ContextHolderAwareRequestWrapper(new MockHttpServletRequest(
                    "/"));

        assertEquals("marissa", wrapper.getRemoteUser());
        assertTrue(wrapper.isUserInRole("ROLE_FOO"));
        assertFalse(wrapper.isUserInRole("ROLE_NOT_GRANTED"));

        ContextHolder.setContext(null);
    }

    public void testCorrectOperationWithUserDetailsBasedPrincipal()
        throws Exception {
        SecureContext sc = new SecureContextImpl();
        Authentication auth = new TestingAuthenticationToken(new User(
                    "marissaAsUserDetails", "koala", true, true, true,
                    new GrantedAuthority[] {}), "koala",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_HELLO"), new GrantedAuthorityImpl(
                        "ROLE_FOOBAR")});
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        ContextHolderAwareRequestWrapper wrapper = new ContextHolderAwareRequestWrapper(new MockHttpServletRequest(
                    "/"));

        assertEquals("marissaAsUserDetails", wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_FOO"));
        assertFalse(wrapper.isUserInRole("ROLE_NOT_GRANTED"));
        assertTrue(wrapper.isUserInRole("ROLE_FOOBAR"));
        assertTrue(wrapper.isUserInRole("ROLE_HELLO"));

        ContextHolder.setContext(null);
    }

    public void testNullAuthenticationHandling() throws Exception {
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(null);
        ContextHolder.setContext(sc);

        ContextHolderAwareRequestWrapper wrapper = new ContextHolderAwareRequestWrapper(new MockHttpServletRequest(
                    "/"));
        assertNull(wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_ANY"));

        ContextHolder.setContext(null);
    }

    public void testNullContextHolderHandling() throws Exception {
        ContextHolder.setContext(null);

        ContextHolderAwareRequestWrapper wrapper = new ContextHolderAwareRequestWrapper(new MockHttpServletRequest(
                    "/"));
        assertNull(wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_ANY"));
    }

    public void testNullPrincipalHandling() throws Exception {
        SecureContext sc = new SecureContextImpl();
        Authentication auth = new TestingAuthenticationToken(null, "koala",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_HELLO"), new GrantedAuthorityImpl(
                        "ROLE_FOOBAR")});
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        ContextHolderAwareRequestWrapper wrapper = new ContextHolderAwareRequestWrapper(new MockHttpServletRequest(
                    "/"));

        assertNull(wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_HELLO")); // principal is null, so reject
        assertFalse(wrapper.isUserInRole("ROLE_FOOBAR")); // principal is null, so reject

        ContextHolder.setContext(null);
    }
}

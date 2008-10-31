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

package org.springframework.security.taglibs.velocity;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.userdetails.User;
import org.springframework.security.util.AuthorityUtils;


public class AuthzImplTests extends TestCase {
    //~ Instance fields ================================================================================================

    private Authz authz = new AuthzImpl();

    //~ Methods ========================================================================================================

    public void testOperationWhenPrincipalIsAString() {
        Authentication auth = new TestingAuthenticationToken("rodAsString", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertEquals("rodAsString", authz.getPrincipal());
    }

    public void testOperationWhenPrincipalIsAUserDetailsInstance() {
        Authentication auth = new TestingAuthenticationToken(new User("rodUserDetails", "koala", true, true, true,
                    true, AuthorityUtils.NO_AUTHORITIES), "koala", AuthorityUtils.NO_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertEquals("rodUserDetails", authz.getPrincipal());
    }

    public void testOperationWhenPrincipalIsNull() {
        Authentication auth = new TestingAuthenticationToken(null, "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertNull(authz.getPrincipal());
    }

    public void testOperationWhenSecurityContextIsNull() {
        SecurityContextHolder.getContext().setAuthentication(null);

        assertEquals(null, authz.getPrincipal());

        SecurityContextHolder.getContext().setAuthentication(null);
    }
}

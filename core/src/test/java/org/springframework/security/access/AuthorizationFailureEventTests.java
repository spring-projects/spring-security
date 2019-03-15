/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access;

import static org.junit.Assert.assertSame;

import org.junit.Test;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;

import java.util.*;


/**
 * Tests {@link AuthorizationFailureEvent}.
 *
 * @author Ben Alex
 */
public class AuthorizationFailureEventTests {
    private final UsernamePasswordAuthenticationToken foo = new UsernamePasswordAuthenticationToken("foo", "bar");
    private List<ConfigAttribute> attributes = SecurityConfig.createList("TEST");
    private AccessDeniedException exception = new AuthorizationServiceException("error", new Throwable());

    @Test(expected=IllegalArgumentException.class)
    public void rejectsNullSecureObject() {
        new AuthorizationFailureEvent(null, attributes, foo, exception);
    }

    @Test(expected=IllegalArgumentException.class)
    public void rejectsNullAttributesList() {
        new AuthorizationFailureEvent(new SimpleMethodInvocation(), null, foo, exception);
    }

    @Test(expected=IllegalArgumentException.class)
    public void rejectsNullAuthentication() {
        new AuthorizationFailureEvent(new SimpleMethodInvocation(), attributes, null, exception);
    }

    @Test(expected=IllegalArgumentException.class)
    public void rejectsNullException() {
        new AuthorizationFailureEvent(new SimpleMethodInvocation(), attributes, foo, null);
    }

    @Test
    public void gettersReturnCtorSuppliedData() throws Exception {
        AuthorizationFailureEvent event = new AuthorizationFailureEvent(new Object(), attributes , foo, exception);
        assertSame(attributes, event.getConfigAttributes());
        assertSame(exception, event.getAccessDeniedException());
        assertSame(foo, event.getAuthentication());
    }
}

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

package org.springframework.security.event.authorization;

import org.junit.Test;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.SecurityConfig;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;


/**
 * Tests {@link AuthorizationFailureEvent}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthorizationFailureEventTests {

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNulls() {
        new AuthorizationFailureEvent(null, SecurityConfig.createList("TEST"),
            new UsernamePasswordAuthenticationToken("foo", "bar"), new AccessDeniedException("error"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNulls2() {
        new AuthorizationFailureEvent(new SimpleMethodInvocation(), null,
            new UsernamePasswordAuthenticationToken("foo", "bar"), new AccessDeniedException("error"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNulls3() {
        new AuthorizationFailureEvent(new SimpleMethodInvocation(), SecurityConfig.createList("TEST"), null,
            new AccessDeniedException("error"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNulls4() {
        new AuthorizationFailureEvent(new SimpleMethodInvocation(), SecurityConfig.createList("TEST"),
            new UsernamePasswordAuthenticationToken("foo", "bar"), null);
    }
}

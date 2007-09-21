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

package org.springframework.security.concurrent;

import org.springframework.security.Authentication;

import org.springframework.security.userdetails.UserDetails;

import org.springframework.util.Assert;


/**
 * Utility methods to assist with concurrent session management.
 *
 * @author Ben Alex
 * @version $Id$
 */
public final class SessionRegistryUtils {
    //~ Constructors ===================================================================================================

    private SessionRegistryUtils() {
    }

    //~ Methods ========================================================================================================

    public static Object obtainPrincipalFromAuthentication(Authentication auth) {
        Assert.notNull(auth, "Authentication required");
        Assert.notNull(auth.getPrincipal(), "Authentication.getPrincipal() required");

        if (auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            return auth.getPrincipal();
        }
    }

    public static String obtainSessionIdFromAuthentication(Authentication auth) {
        Assert.notNull(auth, "Authentication required");
        Assert.notNull(auth.getDetails(), "Authentication.getDetails() required");
        Assert.isInstanceOf(SessionIdentifierAware.class, auth.getDetails());

        String sessionId = ((SessionIdentifierAware) auth.getDetails()).getSessionId();
        Assert.hasText(sessionId, "SessionIdentifierAware did not return a Session ID (" + auth.getDetails() + ")");

        return sessionId;
    }
}

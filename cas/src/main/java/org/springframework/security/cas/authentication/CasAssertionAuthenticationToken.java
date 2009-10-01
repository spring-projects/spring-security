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
package org.springframework.security.cas.authentication;

import java.util.ArrayList;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Temporary authentication object needed to load the user details service.
 *
 * @author Scott Battaglia
 * @version $Id$
 * @since 3.0
 */
public final class CasAssertionAuthenticationToken extends AbstractAuthenticationToken {

    private final Assertion assertion;

    private final String ticket;

    public CasAssertionAuthenticationToken(final Assertion assertion, final String ticket) {
        super(new ArrayList<GrantedAuthority>());

        this.assertion = assertion;
        this.ticket = ticket;
    }

    public Object getPrincipal() {
        return this.assertion.getPrincipal().getName();
    }

    public Object getCredentials() {
        return this.ticket;
    }

    public Assertion getAssertion() {
        return this.assertion;
    }
}

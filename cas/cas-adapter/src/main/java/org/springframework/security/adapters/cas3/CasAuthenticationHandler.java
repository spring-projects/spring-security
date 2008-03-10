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

package org.springframework.security.adapters.cas3;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationManager;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.inspektr.common.ioc.annotation.NotNull;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

/**
 * <p>Provides JA-SIG CAS 3 authentication by delegating to the Spring Security <code>AuthenticationManager</code>.</p>
 *  <p>This class would be configured in the <code>webapp/WEB-INF/deployerConfigContext.xml</code> file in the CAS
 * distribution.</p>
 *
 * @author Scott Battaglia
 * @version $Id:CasAuthenticationHandler.java 2151 2007-09-22 11:54:13Z luke_t $
 *
 * @see AuthenticationHandler
 * @see AuthenticationManager
 */
public final class CasAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {
    //~ Instance fields ================================================================================================

	@NotNull
    private AuthenticationManager authenticationManager;
	
    protected boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials credentials)
        throws AuthenticationException {
        final Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(credentials.getUsername(),
                credentials.getPassword());

        if (log.isDebugEnabled()) {
            log.debug("Attempting to authenticate for user: " + credentials.getUsername());
        }

        try {
            this.authenticationManager.authenticate(authenticationRequest);
        } catch (final org.springframework.security.AuthenticationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication request for " + credentials.getUsername() + " failed: " + e.toString(), e);
            }

            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication request for " + credentials.getUsername() + " successful.");
        }

        return true;
    }

    /**
     * Method to set the Spring Security <code>AuthenticationManager</code> to delegate to.
     *
     * @param authenticationManager the Spring Security AuthenticationManager that knows how to authenticate users.
     */
    public void setAuthenticationManager(final AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
}

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

package org.acegisecurity.adapters.cas3;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

import org.springframework.util.Assert;


/**
 * <p>Provides JA-SIG CAS 3 authentication by delegating to the Acegi <code>AuthenticationManager</code>.</p>
 *  <p>This class would be configured in the <code>webapp/WEB-INF/deployerConfigContext.xml</code> file in the CAS
 * distribution.</p>
 *
 * @author Scott Battaglia
 * @version $Id$
 *
 * @see AuthenticationHandler
 * @see AuthenticationManager
 */
public final class CasAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {
    //~ Instance fields ================================================================================================

    private AuthenticationManager authenticationManager;
    private Log log = LogFactory.getLog(this.getClass());

    //~ Methods ========================================================================================================

    protected void afterPropertiesSetInternal() throws Exception {
        Assert.notNull(this.authenticationManager, "authenticationManager cannot be null.");
    }

    protected boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials credentials)
        throws AuthenticationException {
        final Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(credentials.getUsername(),
                credentials.getPassword());

        if (log.isDebugEnabled()) {
            log.debug("Attempting to authenticate for user: " + credentials.getUsername());
        }

        try {
            this.authenticationManager.authenticate(authenticationRequest);
        } catch (final org.acegisecurity.AuthenticationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication request for " + credentials.getUsername() + "failed: " + e.toString());
            }

            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication request for " + credentials.getUsername() + " successful.");
        }

        return true;
    }

    /**
     * Method to set the Acegi <code>AuthenticationManager</code> to delegate to.
     *
     * @param authenticationManager the Acegi AuthenticationManager that knows how to authenticate users.
     */
    public void setAuthenticationManager(final AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
}

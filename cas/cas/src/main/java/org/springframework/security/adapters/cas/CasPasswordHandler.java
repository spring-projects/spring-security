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

package org.springframework.security.adapters.cas;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import javax.servlet.ServletRequest;


/**
 * Provides actual CAS authentication by delegation to an <code>AuthenticationManager</code>.<P>Do not use this
 * class directly. Instead configure CAS to use the {@link CasPasswordHandlerProxy}.</p>
 *
 * @author Ben Alex
 * @version $Id:CasPasswordHandler.java 2151 2007-09-22 11:54:13Z luke_t $
 */
public final class CasPasswordHandler implements InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(CasPasswordHandler.class);

    //~ Instance fields ================================================================================================

    private AuthenticationManager authenticationManager;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationManager == null) {
            throw new IllegalArgumentException("An AuthenticationManager is required");
        }
    }

    /**
     * Called by <code>CasPasswordHandlerProxy</code> for individual authentication requests.<P>Delegates to
     * the configured <code>AuthenticationManager</code>.</p>
     *
     * @param servletRequest as provided by CAS
     * @param username provided to CAS
     * @param password provided to CAS
     *
     * @return whether authentication was successful or not
     */
    public boolean authenticate(ServletRequest servletRequest, String username, String password) {
        if ((username == null) || "".equals(username)) {
            return false;
        }

        if (password == null) {
            password = "";
        }

        Authentication request = new UsernamePasswordAuthenticationToken(username.toString(), password.toString());
        Authentication response = null;

        try {
            response = authenticationManager.authenticate(request);
        } catch (AuthenticationException failed) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication request for user: " + username + " failed: " + failed.toString());
            }

            return false;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request for user: " + username + " successful");
        }

        return true;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
}

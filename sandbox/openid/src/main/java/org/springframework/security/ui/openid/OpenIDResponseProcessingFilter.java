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
package org.springframework.security.ui.openid;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;

import org.springframework.security.providers.openid.OpenIDAuthenticationToken;

import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;


/**
 * Process the response from the OpenID server to the returnTo URL.
 *
 * @author Robin Bramley, Opsera Ltd
 * @version $Id:$
 */
public class OpenIDResponseProcessingFilter extends AbstractProcessingFilter {
    //~ Instance fields ================================================================================================

    private OpenIDConsumer consumer;

    //~ Methods ========================================================================================================

    /* (non-Javadoc)
     * @see org.springframework.security.ui.AbstractProcessingFilter#attemptAuthentication(javax.servlet.http.HttpServletRequest)
     * @Override
     */
    public Authentication attemptAuthentication(HttpServletRequest req)
        throws AuthenticationException {
        OpenIDAuthenticationToken token;

        try {
            token = consumer.endConsumption(req);
        } catch (OpenIDConsumerException oice) {
            throw new AuthenticationServiceException("Consumer error", oice);
        }

        // delegate to the auth provider
        Authentication authentication = this.getAuthenticationManager().authenticate(token);

        if (authentication.isAuthenticated()) {
            req.getSession()
               .setAttribute(AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY, token.getIdentityUrl());
        }

        return authentication;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.ui.AbstractProcessingFilter#getDefaultFilterProcessesUrl()
     * @Override
     */
    public String getDefaultFilterProcessesUrl() {
        return "/j_spring_openid_security_check";
    }

    // dependency injection
    /**
     * DOCUMENT ME!
     *
     * @param consumer The OpenIDConsumer to set.
     */
    public void setConsumer(OpenIDConsumer consumer) {
        this.consumer = consumer;
    }
}

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

package org.springframework.security.web.authentication;


import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;


/**
 * Detects if there is no {@code Authentication} object in the {@code SecurityContextHolder}, and
 * populates it with one if needed.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean  implements InitializingBean {

    //~ Instance fields ================================================================================================

    private AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private String key;
    private UserAttribute userAttribute;

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(userAttribute);
        Assert.hasLength(key);
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        if (applyAnonymousForThisRequest((HttpServletRequest) req)) {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                SecurityContextHolder.getContext().setAuthentication(createAuthentication((HttpServletRequest) req));

                if (logger.isDebugEnabled()) {
                    logger.debug("Populated SecurityContextHolder with anonymous token: '"
                        + SecurityContextHolder.getContext().getAuthentication() + "'");
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("SecurityContextHolder not populated with anonymous token, as it already contained: '"
                        + SecurityContextHolder.getContext().getAuthentication() + "'");
                }
            }
        }

        chain.doFilter(req, res);
    }

    /**
     * Enables subclasses to determine whether or not an anonymous authentication token should be setup for
     * this request. This is useful if anonymous authentication should be allowed only for specific IP subnet ranges
     * etc.
     *
     * @param request to assist the method determine request details
     *
     * @return <code>true</code> if the anonymous token should be setup for this request (provided that the request
     *         doesn't already have some other <code>Authentication</code> inside it), or <code>false</code> if no
     *         anonymous token should be setup for this request
     */
    protected boolean applyAnonymousForThisRequest(HttpServletRequest request) {
        return true;
    }

    protected Authentication createAuthentication(HttpServletRequest request) {
        AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken(key, userAttribute.getPassword(),
                userAttribute.getAuthorities());
        auth.setDetails(authenticationDetailsSource.buildDetails(request));

        return auth;
    }

    public String getKey() {
        return key;
    }

    public UserAttribute getUserAttribute() {
        return userAttribute;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setUserAttribute(UserAttribute userAttributeDefinition) {
        this.userAttribute = userAttributeDefinition;
    }
}

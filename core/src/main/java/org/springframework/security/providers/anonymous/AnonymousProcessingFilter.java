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

package org.springframework.security.providers.anonymous;

import org.springframework.security.Authentication;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.ui.AuthenticationDetailsSource;
import org.springframework.security.ui.AuthenticationDetailsSourceImpl;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;

import org.springframework.security.userdetails.memory.UserAttribute;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Detects if there is no <code>Authentication</code> object in the <code>SecurityContextHolder</code>,  and
 * populates it with one if needed.<p><b>Do not use this class directly.</b> Instead configure <code>web.xml</code>
 * to use the {@link org.springframework.security.util.FilterToBeanProxy}.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AnonymousProcessingFilter  extends SpringSecurityFilter  implements InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(AnonymousProcessingFilter.class);

    //~ Instance fields ================================================================================================

    private AuthenticationDetailsSource authenticationDetailsSource = new AuthenticationDetailsSourceImpl();
    private String key;
    private UserAttribute userAttribute;
    private boolean removeAfterRequest = true;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userAttribute);
        Assert.hasLength(key);
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
        auth.setDetails(authenticationDetailsSource.buildDetails((HttpServletRequest) request));

        return auth;
    }

	protected void doFilterHttp(HttpServletRequest request,HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        boolean addedToken = false;

        if (applyAnonymousForThisRequest(request)) {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                SecurityContextHolder.getContext().setAuthentication(createAuthentication(request));
                addedToken = true;

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

        try {
            chain.doFilter(request, response);
        } finally {
            if (addedToken && removeAfterRequest
                && createAuthentication(request).equals(SecurityContextHolder.getContext().getAuthentication())) {
                SecurityContextHolder.getContext().setAuthentication(null);
            }
        }
	}

	public int getOrder() {
        return FilterChainOrder.ANONYMOUS_FILTER;
	}

    public String getKey() {
        return key;
    }

    public UserAttribute getUserAttribute() {
        return userAttribute;
    }

    public boolean isRemoveAfterRequest() {
        return removeAfterRequest;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setKey(String key) {
        this.key = key;
    }

    /**
     * Controls whether the filter will remove the Anonymous token after the request is complete. Generally
     * this is desired to avoid the expense of a session being created by {@link
     * org.springframework.security.context.HttpSessionContextIntegrationFilter HttpSessionContextIntegrationFilter} simply to
     * store the Anonymous authentication token.<p>Defaults to <code>true</code>, being the most optimal and
     * appropriate option (ie <code>AnonymousProcessingFilter</code> will clear the token at the end of each request,
     * thus avoiding the session creation overhead in a typical configuration.</p>
     *
     * @param removeAfterRequest DOCUMENT ME!
     */
    public void setRemoveAfterRequest(boolean removeAfterRequest) {
        this.removeAfterRequest = removeAfterRequest;
    }

    public void setUserAttribute(UserAttribute userAttributeDefinition) {
        this.userAttribute = userAttributeDefinition;
    }
}

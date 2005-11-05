/* Copyright 2004, 2005 Acegi Technology Pty Limited
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
package net.sf.acegisecurity.providers.anonymous;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.providers.dao.memory.UserAttribute;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Detects if there is no <code>Authentication</code> object in the
 * <code>SecurityContextHolder</code>,  and populates it with one if needed.
 *
 * <p>
 * <b>Do not use this class directly.</b> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AnonymousProcessingFilter implements Filter, InitializingBean {
    private static final Log logger = LogFactory.getLog(AnonymousProcessingFilter.class);
    private String key;
    private UserAttribute userAttribute;
    private boolean removeAfterRequest = true;

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setUserAttribute(UserAttribute userAttributeDefinition) {
        this.userAttribute = userAttributeDefinition;
    }

    public UserAttribute getUserAttribute() {
        return userAttribute;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userAttribute);
        Assert.hasLength(key);
    }

    /**
     * Does nothing - we reply on IoC lifecycle services instead.
     */
    public void destroy() {
    }

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        boolean addedToken = false;

        if (applyAnonymousForThisRequest(request)) {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                SecurityContextHolder.getContext().setAuthentication(createAuthentication(
                        request));
                addedToken = true;

                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "Populated SecurityContextHolder with anonymous token: '" +
                        SecurityContextHolder.getContext().getAuthentication() +
                        "'");
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "SecurityContextHolder not populated with anonymous token, as it already contained: '" +
                        SecurityContextHolder.getContext().getAuthentication() +
                        "'");
                }
            }
        }

        try {
            chain.doFilter(request, response);
        } finally {
            if (addedToken && removeAfterRequest) {
                SecurityContextHolder.getContext().setAuthentication(null);
            }
        }
    }

    /**
     * Does nothing - we reply on IoC lifecycle services instead.
     *
     * @param ignored not used
     *
     */
    public void init(FilterConfig ignored) throws ServletException {
    }

    /**
     * Enables subclasses to determine whether or not an anonymous
     * authentication token should be setup for this request. This is useful
     * if anonymous authentication should be allowed only for specific IP
     * subnet ranges etc.
     *
     * @param request to assist the method determine request details
     *
     * @return <code>true</code> if the anonymous token should be setup for
     *         this request (provided that the request doesn't already have
     *         some other <code>Authentication</code> inside it), or
     *         <code>false</code> if no anonymous token should be setup for
     *         this request
     */
    protected boolean applyAnonymousForThisRequest(ServletRequest request) {
        return true;
    }

    protected Authentication createAuthentication(ServletRequest request) {
        return new AnonymousAuthenticationToken(key,
            userAttribute.getPassword(), userAttribute.getAuthorities());
    }

    public boolean isRemoveAfterRequest() {
        return removeAfterRequest;
    }

    /**
     * Controls whether the filter will remove the Anonymous token
     * after the request is complete. Generally this is desired to
     * avoid the expense of a session being created by
     * {@link net.sf.acegisecurity.context.HttpSessionContextIntegrationFilter HttpSessionContextIntegrationFilter}
     * simply to store the Anonymous authentication token.
     *
     * <p>Defaults to <code>true</code>,
     * being the most optimal and appropriate option (ie <code>AnonymousProcessingFilter</code>
     * will clear the token at the end of each request, thus avoiding the session creation
     * overhead in a typical configuration.
     */
    public void setRemoveAfterRequest(boolean removeAfterRequest) {
        this.removeAfterRequest = removeAfterRequest;
    }
}

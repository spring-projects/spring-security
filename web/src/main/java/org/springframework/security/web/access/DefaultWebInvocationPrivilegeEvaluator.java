/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.access;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;


/**
 * Allows users to determine whether they have privileges for a given web URI.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(DefaultWebInvocationPrivilegeEvaluator.class);

    //~ Instance fields ================================================================================================

    private final AbstractSecurityInterceptor securityInterceptor;

    //~ Constructors ===================================================================================================

    public DefaultWebInvocationPrivilegeEvaluator(AbstractSecurityInterceptor securityInterceptor) {
        Assert.notNull(securityInterceptor, "SecurityInterceptor cannot be null");
        Assert.isTrue(FilterInvocation.class.equals(securityInterceptor.getSecureObjectClass()),
            "AbstractSecurityInterceptor does not support FilterInvocations");
        Assert.notNull(securityInterceptor.getAccessDecisionManager(),
            "AbstractSecurityInterceptor must provide a non-null AccessDecisionManager");

        this.securityInterceptor = securityInterceptor;
    }

    //~ Methods ========================================================================================================

    /**
     * Determines whether the user represented by the supplied <tt>Authentication</tt> object is
     * allowed to invoke the supplied URI.
     *
     * @param uri the URI excluding the context path (a default context path setting will be used)
     */
    public boolean isAllowed(String uri, Authentication authentication) {
        return isAllowed(null, uri, null, authentication);
    }

    /**
     * Determines whether the user represented by the supplied <tt>Authentication</tt> object is
     * allowed to invoke the supplied URI, with the given .
     * <p>
     * Note the default implementation of <tt>FilterInvocationSecurityMetadataSource</tt> disregards the
     * <code>contextPath</code> when evaluating which secure object metadata applies to a given
     * request URI, so generally the <code>contextPath</code> is unimportant unless you
     * are using a custom <code>FilterInvocationSecurityMetadataSource</code>.
     *
     * @param uri the URI excluding the context path
     * @param contextPath the context path (may be null, in which case a default value will be used).
     * @param method the HTTP method (or null, for any method)
     * @param authentication the <tt>Authentication</tt> instance whose authorities should be used in evaluation
     *          whether access should be granted.
     * @return true if access is allowed, false if denied
     */
    public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
        Assert.notNull(uri, "uri parameter is required");

        FilterInvocation fi = new FilterInvocation(contextPath, uri, method);
        Collection<ConfigAttribute> attrs = securityInterceptor.obtainSecurityMetadataSource().getAttributes(fi);

        if (attrs == null) {
            if (securityInterceptor.isRejectPublicInvocations()) {
                return false;
            }

            return true;
        }

        if (authentication == null) {
            return false;
        }

        try {
            securityInterceptor.getAccessDecisionManager().decide(authentication, fi, attrs);
        } catch (AccessDeniedException unauthorized) {
            if (logger.isDebugEnabled()) {
                logger.debug(fi.toString() + " denied for " + authentication.toString(), unauthorized);
            }

            return false;
        }

        return true;
    }
}



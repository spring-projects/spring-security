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

package org.acegisecurity.intercept.method;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttributeDefinition;

import org.acegisecurity.intercept.AbstractSecurityInterceptor;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;


/**
 * Allows users to determine whether they have "before invocation" privileges
 * for a given method invocation.
 * 
 * <p>
 * Of course, if an {@link org.acegisecurity.AfterInvocationManager} is used to
 * authorize the <em>result</em> of a method invocation, this class cannot
 * assist determine whether or not the <code>AfterInvocationManager</code>
 * will enable access. Instead this class aims to allow applications to
 * determine whether or not the current principal would be allowed to at least
 * attempt to invoke the method, irrespective of the "after" invocation
 * handling.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodInvocationPrivilegeEvaluator implements InitializingBean {
    //~ Instance fields ========================================================

    private AbstractSecurityInterceptor securityInterceptor;

    //~ Methods ================================================================

    public boolean isAllowed(MethodInvocation mi, Authentication authentication) {
        Assert.notNull(authentication, "Authentication required");
        Assert.notNull(authentication.getAuthorities(),
            "Authentication must provided non-null GrantedAuthority[]s");
        Assert.notNull(mi, "MethodInvocation required");
        Assert.notNull(mi.getMethod(),
            "MethodInvocation must provide a non-null getMethod()");

        ConfigAttributeDefinition attrs = securityInterceptor.obtainObjectDefinitionSource()
                                                             .getAttributes(mi);

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
            securityInterceptor.getAccessDecisionManager().decide(authentication,
                mi, attrs);
        } catch (AccessDeniedException unauthorized) {
            unauthorized.printStackTrace();

            return false;
        }

        return true;
    }

    public void setSecurityInterceptor(
        AbstractSecurityInterceptor securityInterceptor) {
        Assert.notNull(securityInterceptor,
            "AbstractSecurityInterceptor cannot be null");
        Assert.isTrue(MethodInvocation.class.equals(
                securityInterceptor.getSecureObjectClass()),
            "AbstractSecurityInterceptor does not support MethodInvocations");
        Assert.notNull(securityInterceptor.getAccessDecisionManager(),
            "AbstractSecurityInterceptor must provide a non-null AccessDecisionManager");
        this.securityInterceptor = securityInterceptor;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(securityInterceptor, "SecurityInterceptor required");
    }
}

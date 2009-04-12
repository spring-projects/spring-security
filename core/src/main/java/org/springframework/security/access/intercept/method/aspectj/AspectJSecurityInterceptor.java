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

package org.springframework.security.access.intercept.method.aspectj;

import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.access.intercept.SecurityMetadataSource;
import org.springframework.security.access.intercept.method.MethodSecurityMetadataSource;

import org.aspectj.lang.JoinPoint;


/**
 * Provides security interception of AspectJ method invocations.
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of type
 * {@link MethodSecurityMetadataSource}. This is shared with the AOP Alliance based security interceptor
 * (<code>MethodSecurityInterceptor</code>),  since both work with Java <code>Method</code>s.
 * <p>
 * The secure object type is <code>org.aspectj.lang.JoinPoint</code>, which is passed from the relevant
 * <code>around()</code> advice. The <code>around()</code> advice also passes an anonymous implementation of {@link
 * AspectJCallback} which contains the call for AspectJ to continue processing:  <code>return proceed();</code>.
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AspectJSecurityInterceptor extends AbstractSecurityInterceptor {
    //~ Instance fields ================================================================================================

    private MethodSecurityMetadataSource securityMetadataSource;

    //~ Methods ========================================================================================================

    public Class<? extends Object> getSecureObjectClass() {
        return JoinPoint.class;
    }

    /**
     * This method should be used to enforce security on a <code>JoinPoint</code>.
     *
     * @param jp The AspectJ joint point being invoked which requires a security decision
     * @param advisorProceed the advice-defined anonymous class that implements <code>AspectJCallback</code> containing
     *        a simple <code>return proceed();</code> statement
     *
     * @return The returned value from the method invocation
     */
    public Object invoke(JoinPoint jp, AspectJCallback advisorProceed) {
        Object result = null;
        InterceptorStatusToken token = super.beforeInvocation(jp);

        try {
            result = advisorProceed.proceedWithObject();
        } finally {
            result = super.afterInvocation(token, result);
        }

        return result;
    }

    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public void setSecurityMetadataSource(MethodSecurityMetadataSource newSource) {
        this.securityMetadataSource = newSource;
    }
}

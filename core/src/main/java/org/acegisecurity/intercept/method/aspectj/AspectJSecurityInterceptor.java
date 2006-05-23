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

package org.acegisecurity.intercept.method.aspectj;

import org.acegisecurity.intercept.AbstractSecurityInterceptor;
import org.acegisecurity.intercept.InterceptorStatusToken;
import org.acegisecurity.intercept.ObjectDefinitionSource;
import org.acegisecurity.intercept.method.MethodDefinitionSource;

import org.aspectj.lang.JoinPoint;


/**
 * Provides security interception of AspectJ method invocations.<p>The <code>ObjectDefinitionSource</code> required
 * by this security interceptor is of type {@link MethodDefinitionSource}. This is shared with the AOP Alliance based
 * security interceptor (<code>MethodSecurityInterceptor</code>),  since both work with Java <code>Method</code>s.</p>
 *  <p>The secure object type is <code>org.aspectj.lang.JoinPoint</code>, which is passed from the relevant
 * <code>around()</code> advice. The <code>around()</code> advice also passes an anonymous implementation of {@link
 * AspectJCallback} which contains the call for AspectJ to continue processing:  <code>return proceed();</code>.</p>
 *  <P>Refer to {@link AbstractSecurityInterceptor} for details on the workflow.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AspectJSecurityInterceptor extends AbstractSecurityInterceptor {
    //~ Instance fields ================================================================================================

    private MethodDefinitionSource objectDefinitionSource;

    //~ Methods ========================================================================================================

    public MethodDefinitionSource getObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public Class getSecureObjectClass() {
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

    public ObjectDefinitionSource obtainObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public void setObjectDefinitionSource(MethodDefinitionSource newSource) {
        this.objectDefinitionSource = newSource;
    }
}

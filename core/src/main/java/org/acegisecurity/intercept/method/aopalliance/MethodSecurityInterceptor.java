/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept.method.aopalliance;

import net.sf.acegisecurity.intercept.AbstractSecurityInterceptor;
import net.sf.acegisecurity.intercept.InterceptorStatusToken;
import net.sf.acegisecurity.intercept.ObjectDefinitionSource;
import net.sf.acegisecurity.intercept.method.MethodDefinitionSource;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;


/**
 * Provides security interception of AOP Alliance based method invocations.
 * 
 * <p>
 * The <code>ObjectDefinitionSource</code> required by this security
 * interceptor is of type {@link MethodDefinitionSource}. This is shared with
 * the AspectJ based security interceptor
 * (<code>AspectJSecurityInterceptor</code>), since both work with Java
 * <code>Method</code>s.
 * </p>
 * 
 * <P>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodSecurityInterceptor extends AbstractSecurityInterceptor
    implements MethodInterceptor {
    //~ Instance fields ========================================================

    private MethodDefinitionSource objectDefinitionSource;

    //~ Methods ================================================================

    public void setObjectDefinitionSource(MethodDefinitionSource newSource) {
        this.objectDefinitionSource = newSource;
    }

    public MethodDefinitionSource getObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public Class getSecureObjectClass() {
        return MethodInvocation.class;
    }

    /**
     * This method should be used to enforce security on a
     * <code>MethodInvocation</code>.
     *
     * @param mi The method being invoked which requires a security decision
     *
     * @return The returned value from the method invocation
     *
     * @throws Throwable if any error occurs
     */
    public Object invoke(MethodInvocation mi) throws Throwable {
        Object result = null;
        InterceptorStatusToken token = super.beforeInvocation(mi);

        try {
            result = mi.proceed();
        } finally {
            result = super.afterInvocation(token, result);
        }

        return result;
    }

    public ObjectDefinitionSource obtainObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }
}

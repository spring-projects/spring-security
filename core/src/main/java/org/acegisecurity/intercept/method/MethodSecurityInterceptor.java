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

package net.sf.acegisecurity.intercept.method;

import net.sf.acegisecurity.intercept.AbstractSecurityInterceptor;
import net.sf.acegisecurity.intercept.ObjectDefinitionSource;
import net.sf.acegisecurity.intercept.SecurityInterceptorCallback;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;


/**
 * Provides security interception of method invocations.
 * 
 * <p>
 * The <code>ObjectDefinitionSource</code> required by this security
 * interceptor is of type {@link MethodDefinitionSource}.
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
    implements MethodInterceptor, SecurityInterceptorCallback {
    //~ Instance fields ========================================================

    private MethodDefinitionSource objectDefinitionSource;

    //~ Methods ================================================================

    public void setObjectDefinitionSource(MethodDefinitionSource newSource) {
        this.objectDefinitionSource = newSource;
    }

    public MethodDefinitionSource getObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public void afterPropertiesSet() {
        super.afterPropertiesSet();

        if (!this.getAccessDecisionManager().supports(MethodInvocation.class)) {
            throw new IllegalArgumentException(
                "AccessDecisionManager does not support MethodInvocation");
        }

        if (!this.getRunAsManager().supports(MethodInvocation.class)) {
            throw new IllegalArgumentException(
                "RunAsManager does not support MethodInvocation");
        }
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
        return super.interceptor(mi, this);
    }

    public ObjectDefinitionSource obtainObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public Object proceedWithObject(Object object) throws Throwable {
        return ((MethodInvocation) object).proceed();
    }
}

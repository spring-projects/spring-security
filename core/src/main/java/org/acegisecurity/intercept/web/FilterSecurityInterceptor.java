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

package net.sf.acegisecurity.intercept.web;

import net.sf.acegisecurity.intercept.AbstractSecurityInterceptor;
import net.sf.acegisecurity.intercept.ObjectDefinitionSource;
import net.sf.acegisecurity.intercept.SecurityInterceptorCallback;


/**
 * Performs security handling of HTTP resources via a filter implementation.
 * 
 * <P>
 * End users should <B>only</B> use this class to configure their HTTP security
 * configuration in an application context. They should <B>not</B> attempt to
 * invoke the <code>FilterSecurityInterceptor</code> except as a standard bean
 * registration in an application context. At runtime, this class will provide
 * services to web applications via the {@link SecurityEnforcementFilter}.
 * </p>
 * 
 * <p>
 * The <code>ObjectDefinitionSource</code> required by this security
 * interceptor is of type {@link FilterInvocationDefinitionSource}.
 * </p>
 * 
 * <P>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor
    implements SecurityInterceptorCallback {
    //~ Instance fields ========================================================

    private FilterInvocationDefinitionSource objectDefinitionSource;

    //~ Methods ================================================================

    public void setObjectDefinitionSource(
        FilterInvocationDefinitionSource newSource) {
        this.objectDefinitionSource = newSource;
    }

    public FilterInvocationDefinitionSource getObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public void afterPropertiesSet() {
        super.afterPropertiesSet();

        if (!this.getAccessDecisionManager().supports(FilterInvocation.class)) {
            throw new IllegalArgumentException(
                "AccessDecisionManager does not support FilterInvocation");
        }

        if (!this.getRunAsManager().supports(FilterInvocation.class)) {
            throw new IllegalArgumentException(
                "RunAsManager does not support FilterInvocation");
        }
    }

    public void invoke(FilterInvocation fi) throws Throwable {
        super.interceptor(fi, this);
    }

    public ObjectDefinitionSource obtainObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public Object proceedWithObject(Object object) throws Throwable {
        FilterInvocation fi = (FilterInvocation) object;
        fi.getChain().doFilter(fi.getRequest(), fi.getResponse());

        return null;
    }
}

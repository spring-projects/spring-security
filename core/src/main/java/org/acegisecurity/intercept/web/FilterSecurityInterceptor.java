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

package org.acegisecurity.intercept.web;

import org.acegisecurity.intercept.AbstractSecurityInterceptor;
import org.acegisecurity.intercept.InterceptorStatusToken;
import org.acegisecurity.intercept.ObjectDefinitionSource;


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
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor {
    //~ Static fields/initializers =============================================

    private static final String FILTER_APPLIED = "__acegi_filterSecurityInterceptor_filterApplied";

    //~ Instance fields ========================================================

    private FilterInvocationDefinitionSource objectDefinitionSource;
    private boolean observeOncePerRequest = true;

    //~ Methods ================================================================

    public void setObjectDefinitionSource(
        FilterInvocationDefinitionSource newSource) {
        this.objectDefinitionSource = newSource;
    }

    public FilterInvocationDefinitionSource getObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }

    /**
     * Indicates whether once-per-request handling will be observed. By default
     * this is <code>true</code>, meaning the
     * <code>FilterSecurityInterceptor</code> will only execute
     * once-per-request. Sometimes users may wish it to execute more than once
     * per request, such as when JSP forwards are being used and filter
     * security is desired on each included fragment of the HTTP request.
     *
     * @return <code>true</code> (the default) if once-per-request is honoured,
     *         otherwise <code>false</code> if
     *         <code>FilterSecurityInterceptor</code> will enforce
     *         authorizations for each and every fragment of the HTTP request.
     */
    public boolean isObserveOncePerRequest() {
        return observeOncePerRequest;
    }

    public Class getSecureObjectClass() {
        return FilterInvocation.class;
    }

    public void invoke(FilterInvocation fi) throws Throwable {
        if ((fi.getRequest() != null)
            && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
            && observeOncePerRequest) {
            // filter already applied to this request and user wants us to observce
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            InterceptorStatusToken token = super.beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.afterInvocation(token, null);
            }
        }
    }

    public ObjectDefinitionSource obtainObjectDefinitionSource() {
        return this.objectDefinitionSource;
    }
}

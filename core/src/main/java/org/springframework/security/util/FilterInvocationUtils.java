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

package org.springframework.security.util;

import org.springframework.security.intercept.web.FilterInvocation;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Static utility methods for creating <code>FilterInvocation</code>s usable within Spring Security.<p>The generated
 * <code>FilterInvocation</code> objects are not intended for use with <code>AbstractSecurityInterceptor</code>
 * subclasses. Instead they are generally used by <code>WebInvocationPrivilegeEvaluator</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public final class FilterInvocationUtils {
    //~ Constructors ===================================================================================================

    private FilterInvocationUtils() {
    }

    //~ Methods ========================================================================================================

    /**
     * Creates a <code>FilterInvocation</code> for the specified <code>contextPath</code> and <code>Uri</code>.
     * Note the normal subclasses of <code>AbstractFilterInvocationDefinitionSource</code> disregard the
     * <code>contextPath</code> when evaluating which secure object metadata applies to a given
     * <code>FilterInvocation</code>, so generally the <code>contextPath</code> is unimportant unless you are using a
     * custom <code>FilterInvocationDefinitionSource</code>.
     *
     * @param contextPath the <code>contextPath</code> that will be contained within the
     *        <code>FilterInvocation</code><code>HttpServletRequest</code>
     * @param uri the URI of the request, such as <code>/foo/default.jsp</code>
     *
     * @return a fully-formed <code>FilterInvocation</code> (never <code>null</code>)
     *
     * @throws UnsupportedOperationException DOCUMENT ME!
     */
    public static FilterInvocation create(String contextPath, String uri) {
        Assert.hasText(contextPath, "contextPath required");
        Assert.hasText(uri, "URI required");

        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRequestURI(contextPath + uri);
        req.setContextPath(contextPath);
        req.setServletPath(null);

        FilterInvocation fi = new FilterInvocation(req, new MockHttpServletResponse(),
                new FilterChain() {
                    public void doFilter(ServletRequest arg0, ServletResponse arg1)
                        throws IOException, ServletException {
                        throw new UnsupportedOperationException(
                            "WebInvocationPrivilegeEvaluator does not support filter chains");
                    }
                });

        return fi;
    }

    /**
     * Creates a <code>FilterInvocation</code> for the specified <code>Uri</code>. The <code>contextPath</code>
     * is set to a default value.
     *
     * @param uri the URI of the request, such as <code>/foo/default.jsp</code>
     *
     * @return a fully-formed <code>FilterInvocation</code> (never <code>null</code>)
     */
    public static FilterInvocation create(String uri) {
        return create("/notused", uri);
    }
}

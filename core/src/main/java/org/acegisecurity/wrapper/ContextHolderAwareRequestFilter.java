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

package net.sf.acegisecurity.wrapper;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;


/**
 * A <code>Filter</code> which populates the <code>ServletRequest</code> with
 * an {@link ContextHolderAwareRequestWrapper}.
 *
 * @author Orlando Garcia Carmona
 * @version $Id$
 */
public class ContextHolderAwareRequestFilter implements Filter {
    //~ Methods ================================================================

    public void destroy() {}

    public void doFilter(ServletRequest servletRequest,
        ServletResponse servletResponse, FilterChain filterChain)
        throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        if (!(request instanceof ContextHolderAwareRequestWrapper)) {
            request = new ContextHolderAwareRequestWrapper(request);
        }

        filterChain.doFilter(request, servletResponse);
    }

    public void init(FilterConfig filterConfig) throws ServletException {}
}

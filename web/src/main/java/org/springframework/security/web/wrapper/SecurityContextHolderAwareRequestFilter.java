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

package org.springframework.security.web.wrapper;

import java.io.IOException;
import java.lang.reflect.Constructor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.SpringSecurityFilter;
import org.springframework.security.web.util.FilterChainOrder;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;


/**
 * A <code>Filter</code> which populates the <code>ServletRequest</code> with a new request wrapper.
 * Several request wrappers are included with the framework. The simplest version is {@link
 * SecurityContextHolderAwareRequestWrapper}. A more complex and powerful request wrapper is
 * {@link SavedRequestAwareWrapper}. The latter is also the default.
 * <p>
 * To modify the wrapper used, call {@link #setWrapperClass(Class)}.
 * <p>
 * Any request wrapper configured for instantiation by this class must provide a public constructor that
 * accepts two arguments, being a <code>HttpServletRequest</code> and a <code>PortResolver</code>.
 *
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityContextHolderAwareRequestFilter extends SpringSecurityFilter {
    //~ Instance fields ================================================================================================

    private Class<? extends HttpServletRequest> wrapperClass = SavedRequestAwareWrapper.class;
    private Constructor<? extends HttpServletRequest> constructor;
    private PortResolver portResolver = new PortResolverImpl();
    private String rolePrefix;

    //~ Methods ========================================================================================================

    public void setPortResolver(PortResolver portResolver) {
        Assert.notNull(portResolver, "PortResolver required");
        this.portResolver = portResolver;
    }

    @SuppressWarnings("unchecked")
    public void setWrapperClass(Class wrapperClass) {
        Assert.notNull(wrapperClass, "WrapperClass required");
        Assert.isTrue(HttpServletRequest.class.isAssignableFrom(wrapperClass), "Wrapper must be a HttpServletRequest");
        this.wrapperClass = wrapperClass;
    }

    public void setRolePrefix(String rolePrefix) {
        Assert.notNull(rolePrefix, "Role prefix must not be null");
        this.rolePrefix = rolePrefix.trim();
    }

    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!wrapperClass.isAssignableFrom(request.getClass())) {
            try {
                if (constructor == null) {
                    constructor = wrapperClass.getConstructor(HttpServletRequest.class, PortResolver.class, String.class);
                }

                request = constructor.newInstance(request, portResolver, rolePrefix);
            } catch (Exception ex) {
                ReflectionUtils.handleReflectionException(ex);
            }
        }

        chain.doFilter(request, response);
    }

    public int getOrder() {
        return FilterChainOrder.SERVLET_API_SUPPORT_FILTER;
    }
}

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

package org.springframework.security.wrapper;

import java.io.IOException;
import java.lang.reflect.Constructor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.security.util.PortResolver;
import org.springframework.security.util.PortResolverImpl;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;


/**
 * A <code>Filter</code> which populates the <code>ServletRequest</code> with a new request wrapper.<p>Several
 * request wrappers are included with the framework. The simplest version is {@link
 * SecurityContextHolderAwareRequestWrapper}. A more complex and powerful request wrapper is {@link
 * org.springframework.security.wrapper.SavedRequestAwareWrapper}. The latter is also the default.</p>
 *  <p>To modify the wrapper used, call {@link #setWrapperClass(Class)}.</p>
 *  <p>Any request wrapper configured for instantiation by this class must provide a public constructor that
 * accepts two arguments, being a <code>HttpServletRequest</code> and a <code>PortResolver</code>.</p>
 *
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityContextHolderAwareRequestFilter extends SpringSecurityFilter {
    //~ Instance fields ================================================================================================

    private Class wrapperClass = SavedRequestAwareWrapper.class;
    private Constructor constructor;
    private PortResolver portResolver = new PortResolverImpl();
    private String rolePrefix;

    //~ Methods ========================================================================================================

    public void setPortResolver(PortResolver portResolver) {
        Assert.notNull(portResolver, "PortResolver required");
        this.portResolver = portResolver;
    }

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
            if (constructor == null) {
                try {
                    constructor = wrapperClass.getConstructor(
                            new Class[] {HttpServletRequest.class, PortResolver.class, String.class});
                } catch (Exception ex) {
                    ReflectionUtils.handleReflectionException(ex);
                }
            }

            try {
                request = (HttpServletRequest) constructor.newInstance(new Object[] {request, portResolver, rolePrefix});
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

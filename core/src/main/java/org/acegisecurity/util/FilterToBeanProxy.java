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

package net.sf.acegisecurity.util;

import org.springframework.context.ApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.IOException;

import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Delegates <code>Filter</code> requests to a Spring-managed bean.
 * 
 * <p>
 * This class acts as a proxy on behalf of a target <code>Filter</code> that is
 * defined in the Spring bean context. It is necessary to specify which target
 * <code>Filter</code> should be proxied as a filter initialization parameter.
 * </p>
 * 
 * <p>
 * On filter initialisation, the class will use Spring's {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * method to obtain an <code>ApplicationContext</code> instance. It will
 * expect to find the target <code>Filter</code> in this
 * <code>ApplicationContext</code>.
 * </p>
 * 
 * <p>
 * To use this filter, it is necessary to specify the following filter
 * initialization parameters:
 * </p>
 * 
 * <ul>
 * <li>
 * <code>targetClass</code> indicates the class of the target
 * <code>Filter</code> defined in the bean context. The only requirements are
 * that this target class implements the <code>javax.servlet.Filter</code>
 * interface and at least one instance is available in the
 * <code>ApplicationContext</code>.
 * </li>
 * <li>
 * <code>targetBean</code> (optional) indicates the bean name of the target
 * class. This parameter should be specified if there is more than one bean in
 * the <code>ApplicationContext</code> of the same type as defined by the
 * <code>targetClass</code> parameter.
 * </li>
 * </ul>
 * 
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterToBeanProxy implements Filter {
    //~ Instance fields ========================================================

    private Filter delegate;

    //~ Methods ================================================================

    public void destroy() {
        delegate.destroy();
    }

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        delegate.doFilter(request, response, chain);
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        String targetClassString = filterConfig.getInitParameter("targetClass");

        if ((targetClassString == null) || "".equals(targetClassString)) {
            throw new ServletException("targetClass must be specified");
        }

        Class targetClass;

        try {
            targetClass = Thread.currentThread().getContextClassLoader()
                                .loadClass(targetClassString);
        } catch (ClassNotFoundException ex) {
            throw new ServletException("Class of type " + targetClassString
                + " not found in classloader");
        }

        String targetBean = filterConfig.getInitParameter("targetBean");

        if ("".equals(targetBean)) {
            targetBean = null;
        }

        ApplicationContext ctx = this.getContext(filterConfig);

        Map beans = ctx.getBeansOfType(targetClass, true, true);

        if (beans.size() == 0) {
            throw new ServletException(
                "Bean context must contain at least one bean of type "
                + targetClassString);
        }

        String beanName = null;

        if (targetBean == null) {
            // Use first bean found
            beanName = (String) beans.keySet().iterator().next();
        } else {
            // Use the requested bean, providing it can be found
            if (beans.containsKey(targetBean)) {
                beanName = targetBean;
            } else {
                throw new ServletException("Bean with name '" + targetBean
                    + "' cannot be found in bean context");
            }
        }

        Object object = beans.get(beanName);

        if (!(object instanceof Filter)) {
            throw new ServletException("Bean '" + beanName
                + "' does not implement javax.servlet.Filter");
        }

        delegate = (Filter) object;

        delegate.init(filterConfig);
    }

    /**
     * Allows test cases to override where application context obtained from.
     *
     * @param filterConfig which can be used to find the
     *        <code>ServletContext</code>
     *
     * @return the Spring application context
     */
    protected ApplicationContext getContext(FilterConfig filterConfig) {
        return WebApplicationContextUtils.getRequiredWebApplicationContext(filterConfig
            .getServletContext());
    }
}

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

import org.springframework.beans.factory.BeanFactoryUtils;

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
 * To use this filter, it is necessary to specify <b>one</b> of the following
 * filter initialization parameters:
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
 * <code>targetBean</code> indicates the bean name of the target class.
 * </li>
 * </ul>
 * 
 * If both initialization parameters are specified, <code>targetBean</code>
 * takes priority.
 * 
 * <P>
 * An additional initialization parameter, <code>init</code>, is also
 * supported. If set to "<code>lazy</code>" the initialization will take place
 * on the first HTTP request, rather than at filter creation time. This makes
 * it possible to use <code>FilterToBeanProxy</code> with the Spring
 * <code>ContextLoaderServlet</code>. Where possible you should not use this
 * initialization parameter, instead using <code>ContextLoaderListener</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterToBeanProxy implements Filter {
    //~ Instance fields ========================================================

    private Filter delegate;
    private FilterConfig filterConfig;
    private boolean initialized = false;

    //~ Methods ================================================================

    public void destroy() {
        if (delegate != null) {
            delegate.destroy();
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (!initialized) {
            doInit();
        }

        delegate.doFilter(request, response, chain);
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;

        String strategy = filterConfig.getInitParameter("init");

        if ((strategy != null) && strategy.toLowerCase().equals("lazy")) {
            return;
        }

        doInit();
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

    private void doInit() throws ServletException {
        initialized = true;

        String targetBean = filterConfig.getInitParameter("targetBean");

        if ("".equals(targetBean)) {
            targetBean = null;
        }

        ApplicationContext ctx = this.getContext(filterConfig);

        String beanName = null;

        if ((targetBean != null) && ctx.containsBean(targetBean)) {
            beanName = targetBean;
        } else if (targetBean != null) {
            throw new ServletException("targetBean '" + targetBean
                + "' not found in context");
        } else {
            String targetClassString = filterConfig.getInitParameter(
                    "targetClass");

            if ((targetClassString == null) || "".equals(targetClassString)) {
                throw new ServletException(
                    "targetClass or targetBean must be specified");
            }

            Class targetClass;

            try {
                targetClass = Thread.currentThread().getContextClassLoader()
                                    .loadClass(targetClassString);
            } catch (ClassNotFoundException ex) {
                throw new ServletException("Class of type " + targetClassString
                    + " not found in classloader");
            }

            Map beans = BeanFactoryUtils.beansOfTypeIncludingAncestors(ctx,
                    targetClass, true, true);

            if (beans.size() == 0) {
                throw new ServletException(
                    "Bean context must contain at least one bean of type "
                    + targetClassString);
            }

            beanName = (String) beans.keySet().iterator().next();
        }

        Object object = ctx.getBean(beanName);

        if (!(object instanceof Filter)) {
            throw new ServletException("Bean '" + beanName
                + "' does not implement javax.servlet.Filter");
        }

        delegate = (Filter) object;

        delegate.init(filterConfig);
    }
}

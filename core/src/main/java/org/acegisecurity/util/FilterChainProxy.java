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

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.intercept.web.FilterInvocationDefinitionSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * Delegates <code>Filter</code> requests to a Spring-managed bean.
 * <p>
 * This class acts as a proxy on behalf of a target <code>Filter</code> that
 * is defined in the Spring bean context. It is necessary to specify which
 * target <code>Filter</code> should be proxied as a filter initialization
 * parameter.
 * </p>
 * <p>
 * On filter initialisation, the class will use Spring's {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * method to obtain an <code>ApplicationContext</code> instance. It will
 * expect to find the target <code>Filter</code> in this
 * <code>ApplicationContext</code>.
 * </p>
 * <p>
 * To use this filter, it is necessary to specify <b>one </b> of the following
 * filter initialization parameters:
 * </p>
 * <ul>
 * <li><code>targetClass</code> indicates the class of the target
 * <code>Filter</code> defined in the bean context. The only requirements are
 * that this target class implements the <code>javax.servlet.Filter</code>
 * interface and at least one instance is available in the
 * <code>ApplicationContext</code>.</li>
 * <li><code>targetBean</code> indicates the bean name of the target class.
 * </li>
 * </ul>
 * If both initialization parameters are specified, <code>targetBean</code>
 * takes priority.
 * <P>
 * An additional initialization parameter, <code>init</code>, is also
 * supported. If set to "<code>lazy</code>" the initialization will take
 * place on the first HTTP request, rather than at filter creation time. This
 * makes it possible to use <code>FilterToBeanProxy</code> with the Spring
 * <code>ContextLoaderServlet</code>. Where possible you should not use this
 * initialization parameter, instead using <code>ContextLoaderListener</code>.
 * </p>
 * 
// * <pre>
// * &lt;bean id=&quot;filterChain&quot; class=&quot;net.sf.acegisecurity.FilterChain&quot;&gt;
// *   &lt;property name=&quot;filters&quot;&gt;
// *   &lt;value&gt;
// *     channelProcessingFilter=/*
// *     authenticationProcessingFilter=/*
// *     basicProcessingFilter=/*
// *     sessionIntegrationFilter=/*
// *     securityEnforcementFilter=/*
// *   &lt;/value&gt;
// *   &lt;/property&gt;
// * &lt;/bean&gt;
// * </pre>
 * 
 * @author Carlos Sanchez
 * @version $Id$
 */
public class FilterChainProxy
    implements Filter, InitializingBean
{
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(FilterChainProxy.class);

    //~ Instance fields
    // ========================================================

    private Filter delegate;

    private List filters;

    private FilterConfig filterConfig;

    private boolean initialized = false;

    private FilterInvocationDefinitionSource filterInvocationDefinitionSource;

    //~ Methods
    // ================================================================

    public void setFilterInvocationDefinitionSource(
        FilterInvocationDefinitionSource filterInvocationDefinitionSource) {
        this.filterInvocationDefinitionSource = filterInvocationDefinitionSource;
    }

    public FilterInvocationDefinitionSource getFilterInvocationDefinitionSource() {
        return filterInvocationDefinitionSource;
    }

    public void destroy()
    {
        Iterator it = filters.iterator();
        while ( it.hasNext() )
        {
            Filter filter = (Filter) it.next();
            if ( filter != null )
            {
                filter.destroy();
            }
        }
    }

    public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain ) throws IOException,
        ServletException
    {
        if ( !initialized )
        {
            doInit();
        }

        Iterator it = filters.iterator();
        while ( it.hasNext() )
        {
            Filter filter = (Filter) it.next();
            filter.doFilter( request, response, chain );
        }
    }

    public void init( FilterConfig filterConfig ) throws ServletException
    {
        this.filterConfig = filterConfig;

        String strategy = filterConfig.getInitParameter( "init" );

        if ( (strategy != null) && strategy.toLowerCase().equals( "lazy" ) )
        {
            return;
        }

        doInit();
    }

    /**
     * Allows test cases to override where application context obtained from.
     * 
     * @param filterConfig
     *            which can be used to find the <code>ServletContext</code>
     * @return the Spring application context
     */
    protected ApplicationContext getContext( FilterConfig filterConfig )
    {
        return WebApplicationContextUtils.getRequiredWebApplicationContext( filterConfig.getServletContext() );
    }

    private void doInit() throws ServletException
    {
        initialized = true;
        
        Iterator it = filters.iterator();
        while ( it.hasNext() )
        {
            Filter filter = (Filter) it.next();
            filter.init( filterConfig );
        }

    }

    public void afterPropertiesSet() throws Exception {
        if (filterInvocationDefinitionSource == null) {
            throw new IllegalArgumentException(
                "filterInvocationDefinitionSource must be specified");
        }

        Iterator iter = this.filterInvocationDefinitionSource
            .getConfigAttributeDefinitions();

        if (iter == null) {
            if (logger.isWarnEnabled()) {
                logger.warn(
                    "Could not validate configuration attributes as the FilterInvocationDefinitionSource did not return a ConfigAttributeDefinition Iterator");
            }

            return;
        }

        Set set = new HashSet();

        while (iter.hasNext()) {
            ConfigAttributeDefinition def = (ConfigAttributeDefinition) iter
                .next();
            Iterator attributes = def.getConfigAttributes();

            while (attributes.hasNext()) {
                ConfigAttribute attr = (ConfigAttribute) attributes.next();
            }
        }

        if (set.size() == 0) {
            if (logger.isInfoEnabled()) {
                logger.info("Validated configuration attributes");
            }
        } else {
            throw new IllegalArgumentException(
                "Unsupported configuration attributes: " + set.toString());
        }
        
        iter = filterInvocationDefinitionSource.getConfigAttributeDefinitions();
        while ( iter.hasNext() )
        {
            ConfigAttributeDefinition element = (ConfigAttributeDefinition) iter.next();
            Iterator configAttributes = element.getConfigAttributes();
        }
    }

}
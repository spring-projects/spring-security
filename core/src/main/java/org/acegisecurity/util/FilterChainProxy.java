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

package org.acegisecurity.util;

import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;

import org.acegisecurity.intercept.web.FilterInvocation;
import org.acegisecurity.intercept.web.FilterInvocationDefinitionSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import org.springframework.util.Assert;

import java.io.IOException;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Delegates <code>Filter</code> requests to a list of Spring-managed beans.<p>The <code>FilterChainProxy</code> is
 * loaded via a standard {@link org.acegisecurity.util.FilterToBeanProxy} declaration in <code>web.xml</code>.
 * <code>FilterChainProxy</code> will then pass {@link #init(FilterConfig)}, {@link #destroy()} and {@link
 * #doFilter(ServletRequest, ServletResponse, FilterChain)} invocations through to each <code>Filter</code> defined
 * against <code>FilterChainProxy</code>.</p>
 *  <p><code>FilterChainProxy</code> is configured using a standard {@link
 * org.acegisecurity.intercept.web.FilterInvocationDefinitionSource}. Each possible URI pattern that
 * <code>FilterChainProxy</code> should service must be entered. The first matching URI pattern located by
 * <code>FilterInvocationDefinitionSource</code> for a given request will be used to define all of the
 * <code>Filter</code>s that apply to that request. NB: This means you must put most specific URI patterns at the top
 * of the list, and ensure all <code>Filter</code>s that should apply for a given URI pattern are entered against the
 * respective entry. The <code>FilterChainProxy</code> will not iterate the remainder of the URI patterns to locate
 * additional <code>Filter</code>s.  The <code>FilterInvocationDefinitionSource</code> described the applicable URI
 * pattern to fire the filter chain, followed by a list of configuration attributes. Each configuration attribute's
 * {@link org.acegisecurity.ConfigAttribute#getAttribute()} corresponds to a bean name that is available from the
 * application context.</p>
 *  <p><code>FilterChainProxy</code> respects normal handling of <code>Filter</code>s that elect not to call {@link
 * javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
 * javax.servlet.FilterChain)}, in that the remainder of the origial or <code>FilterChainProxy</code>-declared filter
 * chain will not be called.</p>
 *  <p>It is particularly noted the <code>Filter</code> lifecycle mismatch between the servlet container and IoC
 * container. As per {@link org.acegisecurity.util.FilterToBeanProxy} JavaDocs, we recommend you allow the IoC
 * container to manage lifecycle instead of the servlet container. By default the <code>FilterToBeanProxy</code> will
 * never call this class' {@link #init(FilterConfig)} and {@link #destroy()} methods, meaning each of the filters
 * defined against <code>FilterInvocationDefinitionSource</code> will not be called. If you do need your filters to be
 * initialized and destroyed, please set the <code>lifecycle</code> initialization parameter against the
 * <code>FilterToBeanProxy</code> to specify servlet container lifecycle management.</p>
 *  <p>If a filter name of {@link #TOKEN_NONE} is used, this allows specification of a filter pattern which should
 * never cause any filters to fire.</p>
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @version $Id$
 */
public class FilterChainProxy implements Filter, InitializingBean, ApplicationContextAware {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(FilterChainProxy.class);
    public static final String TOKEN_NONE = "#NONE#";

    //~ Instance fields ================================================================================================

    private ApplicationContext applicationContext;
    private FilterInvocationDefinitionSource filterInvocationDefinitionSource;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(filterInvocationDefinitionSource, "filterInvocationDefinitionSource must be specified");
        Assert.notNull(this.filterInvocationDefinitionSource.getConfigAttributeDefinitions(),
            "FilterChainProxy requires the FilterInvocationDefinitionSource to return a non-null response to "
                    + "getConfigAttributeDefinitions()");
    }

    public void destroy() {
        Filter[] filters = obtainAllDefinedFilters();

        for (int i = 0; i < filters.length; i++) {
            if (filters[i] != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Destroying Filter defined in ApplicationContext: '" + filters[i].toString() + "'");
                }

                filters[i].destroy();
            }
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        ConfigAttributeDefinition cad = this.filterInvocationDefinitionSource.getAttributes(fi);

        if (cad == null) {
            if (logger.isDebugEnabled()) {
                logger.debug(fi.getRequestUrl() + " has no matching filters");
            }

            chain.doFilter(request, response);

            return;
        }

        Filter[] filters = obtainAllDefinedFilters(cad);

        if (filters.length == 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(fi.getRequestUrl() + " has an empty filter list");
            }

            chain.doFilter(request, response);

            return;
        }

        VirtualFilterChain virtualFilterChain = new VirtualFilterChain(fi, filters);
        virtualFilterChain.doFilter(fi.getRequest(), fi.getResponse());
    }

    public FilterInvocationDefinitionSource getFilterInvocationDefinitionSource() {
        return filterInvocationDefinitionSource;
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        Filter[] filters = obtainAllDefinedFilters();

        for (int i = 0; i < filters.length; i++) {
            if (filters[i] != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Initializing Filter defined in ApplicationContext: '" + filters[i].toString() + "'");
                }

                filters[i].init(filterConfig);
            }
        }
    }

    /**
     * Obtains all of the <b>unique</b><code>Filter</code> instances registered against the
     * <code>FilterInvocationDefinitionSource</code>.<p>This is useful in ensuring a <code>Filter</code> is not
     * initialized or destroyed twice.</p>
     *
     * @return all of the <code>Filter</code> instances in the application context for which there has been an entry
     *         against the <code>FilterInvocationDefinitionSource</code> (only one entry is included in the array for
     *         each <code>Filter</code> that actually exists in application context, even if a given
     *         <code>Filter</code> is defined multiples times by the <code>FilterInvocationDefinitionSource</code>)
     */
    protected Filter[] obtainAllDefinedFilters() {
        Iterator cads = this.filterInvocationDefinitionSource.getConfigAttributeDefinitions();
        Set list = new LinkedHashSet();

        while (cads.hasNext()) {
            ConfigAttributeDefinition attribDef = (ConfigAttributeDefinition) cads.next();
            Filter[] filters = obtainAllDefinedFilters(attribDef);

            for (int i = 0; i < filters.length; i++) {
                list.add(filters[i]);
            }
        }

        return (Filter[]) list.toArray(new Filter[0]);
    }

    /**
     * Obtains all of the <code>Filter</code> instances registered against the specified
     * <code>ConfigAttributeDefinition</code>.
     *
     * @param configAttributeDefinition for which we want to obtain associated <code>Filter</code>s
     *
     * @return the <code>Filter</code>s against the specified <code>ConfigAttributeDefinition</code> (never
     *         <code>null</code>)
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    private Filter[] obtainAllDefinedFilters(ConfigAttributeDefinition configAttributeDefinition) {
        List list = new Vector();
        Iterator attributes = configAttributeDefinition.getConfigAttributes();

        while (attributes.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) attributes.next();
            String filterName = attr.getAttribute();

            if (filterName == null) {
                throw new IllegalArgumentException("Configuration attribute: '" + attr
                    + "' returned null to the getAttribute() method, which is invalid when used with FilterChainProxy");
            }

            if (!filterName.equals(TOKEN_NONE)) {
                list.add(this.applicationContext.getBean(filterName, Filter.class));
            }
        }

        return (Filter[]) list.toArray(new Filter[list.size()]);
    }

    public void setApplicationContext(ApplicationContext applicationContext)
        throws BeansException {
        this.applicationContext = applicationContext;
    }

    public void setFilterInvocationDefinitionSource(FilterInvocationDefinitionSource filterInvocationDefinitionSource) {
        this.filterInvocationDefinitionSource = filterInvocationDefinitionSource;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * A <code>FilterChain</code> that records whether or not {@link
     * FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} is called.<p>This
     * <code>FilterChain</code> is used by <code>FilterChainProxy</code> to determine if the next <code>Filter</code>
     * should be called or not.</p>
     */
    private class VirtualFilterChain implements FilterChain {
        private FilterInvocation fi;
        private Filter[] additionalFilters;
        private int currentPosition = 0;

        public VirtualFilterChain(FilterInvocation filterInvocation, Filter[] additionalFilters) {
            this.fi = filterInvocation;
            this.additionalFilters = additionalFilters;
        }

        private VirtualFilterChain() {}

        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (currentPosition == additionalFilters.length) {
                if (logger.isDebugEnabled()) {
                    logger.debug(fi.getRequestUrl()
                        + " reached end of additional filter chain; proceeding with original chain");
                }

                fi.getChain().doFilter(request, response);
            } else {
                currentPosition++;

                if (logger.isDebugEnabled()) {
                    logger.debug(fi.getRequestUrl() + " at position " + currentPosition + " of "
                        + additionalFilters.length + " in additional filter chain; firing Filter: '"
                        + additionalFilters[currentPosition - 1] + "'");
                }

                additionalFilters[currentPosition - 1].doFilter(request, response, this);
            }
        }
    }
}

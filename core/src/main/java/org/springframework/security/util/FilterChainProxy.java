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
import org.springframework.security.intercept.web.FilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.FilterChainMap;
import org.springframework.security.intercept.web.FIDSToFilterChainMapConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Delegates <code>Filter</code> requests to a list of Spring-managed beans.
 * As of version 2.0, you shouldn't need to explicitly configure a <tt>FilterChainProxy</tt> bean in your application
 * context unless you need very fine control over the filter chain contents. Most cases should be adequately covered
 * by the default <tt>&lt;security:http /&gt</tt> namespace configuration options.
 *
 * <p>The <code>FilterChainProxy</code> is loaded via a standard
 * {@link org.springframework.security.util.FilterToBeanProxy} declaration in <code>web.xml</code>.
 * <code>FilterChainProxy</code> will then pass {@link #init(FilterConfig)}, {@link #destroy()} and {@link
 * #doFilter(ServletRequest, ServletResponse, FilterChain)} invocations through to each <code>Filter</code> defined
 * against <code>FilterChainProxy</code>.</p>
 *
 * <p>As of version 2.0, <tt>FilterChainProxy</tt> is configured using a {@link FilterChainMap}. In previous
 * versions, a {@link FilterInvocationDefinitionSource} was used. This is now deprecated in favour of namespace-based
 * configuration which provides a more robust and simplfied syntax.  The <tt>FilterChainMap</tt> instance will be
 * created while parsing the namespace configuration, so it doesn't require an explicit bean declaration.
 * Instead the &lt;filter-chain-map&gt; element should be used within the FilterChainProxy bean declaration.
 * This in turn should have a list of child &lt;filter-chain&gt; elements which each define a URI pattern and the list
 * of filters (as comma-separated bean names) which should be applied to requests which match the pattern.
 * An example configuration might look like this:
 *
 * <pre>
 &lt;bean id="myfilterChainProxy" class="org.springframework.security.util.FilterChainProxy">
     &lt;security:filter-chain-map pathType="ant">
         &lt;security:filter-chain pattern="/do/not/filter" filters="none"/>
         &lt;security:filter-chain pattern="/**" filters="filter1,filter2,filter3"/>
     &lt;/security:filter-chain-map>
 &lt;/bean>
 * </pre>
 *
 * The names "filter1", "filter2", "filter3" should be the bean names of <tt>Filter</tt> instances defined in the
 * application context. The order of the names defines the order in which the filters will be applied. As shown above,
 * use of the value "none" for the "filters" can be used to exclude
 * Please consult the security namespace schema file for a full list of available configuration options.
 * </p>
 *
 *<p>
 * Each possible URI pattern that <code>FilterChainProxy</code> should service must be entered.
 * The first matching URI pattern for a given request will be used to define all of the
 * <code>Filter</code>s that apply to that request. NB: This means you must put most specific URI patterns at the top
 * of the list, and ensure all <code>Filter</code>s that should apply for a given URI pattern are entered against the
 * respective entry. The <code>FilterChainProxy</code> will not iterate the remainder of the URI patterns to locate
 * additional <code>Filter</code>s.</p>
 *  <p><code>FilterChainProxy</code> respects normal handling of <code>Filter</code>s that elect not to call {@link
 * javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
 * javax.servlet.FilterChain)}, in that the remainder of the origial or <code>FilterChainProxy</code>-declared filter
 * chain will not be called.</p>
 *  <p>It is particularly noted the <code>Filter</code> lifecycle mismatch between the servlet container and IoC
 * container. As per {@link org.springframework.security.util.FilterToBeanProxy} JavaDocs, we recommend you allow the IoC
 * container to manage lifecycle instead of the servlet container. By default the <code>FilterToBeanProxy</code> will
 * never call this class' {@link #init(FilterConfig)} and {@link #destroy()} methods, meaning each of the filters
 * defined in the FilterChainMap will not be called. If you do need your filters to be
 * initialized and destroyed, please set the <code>lifecycle</code> initialization parameter against the
 * <code>FilterToBeanProxy</code> to specify servlet container lifecycle management.</p>
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 *
 * @version $Id$
 */
public class FilterChainProxy implements Filter, InitializingBean, ApplicationContextAware {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(FilterChainProxy.class);
    public static final String TOKEN_NONE = "#NONE#";

    //~ Instance fields ================================================================================================

    private ApplicationContext applicationContext;
    private FilterChainMap filterChainMap;
    private FilterInvocationDefinitionSource fids;
    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        // Convert the FilterDefinitionSource to a filterChainMap if set
        if (fids != null) {
            Assert.isNull(filterChainMap, "Set the FilterChainMap or FilterInvocationDefinitionSource but not both");
            setFilterChainMap(new FIDSToFilterChainMapConverter(fids, applicationContext).getFilterChainMap());
        }

        Assert.notNull(filterChainMap, "A FilterChainMap must be supplied");
    }

    public void destroy() {
        Filter[] filters = filterChainMap.getAllDefinedFilters();

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

        Filter[] filters = filterChainMap.getFilters(fi.getRequestUrl());

        if (filters == null || filters.length == 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(fi.getRequestUrl() +
                        filters == null ? " has no matching filters" : " has an empty filter list");
            }

            chain.doFilter(request, response);

            return;
        }

        VirtualFilterChain virtualFilterChain = new VirtualFilterChain(fi, filters);
        virtualFilterChain.doFilter(fi.getRequest(), fi.getResponse());
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        Filter[] filters = filterChainMap.getAllDefinedFilters();

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
     * Obtains all of the <b>unique</b><code>Filter</code> instances registered in the
     * <code>FilterChainMap</code>.
     * <p>This is useful in ensuring a <code>Filter</code> is not
     * initialized or destroyed twice.</p>
     *
     * @deprecated
     * @return all of the <code>Filter</code> instances in the application context which have an entry
     *         in the <code>FilterChainMap</code> (only one entry is included in the array for
     *         each <code>Filter</code> that actually exists in application context, even if a given
     *         <code>Filter</code> is defined multiples times by the <code>FilterChainMap</code>)
     */
    protected Filter[] obtainAllDefinedFilters() {
        return filterChainMap.getAllDefinedFilters();
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    /**
     *
     * @deprecated Use namespace configuration or call setFilterChainMap instead.
     */
    public void setFilterInvocationDefinitionSource(FilterInvocationDefinitionSource fids) {
        this.fids = fids;
    }

    public void setFilterChainMap(FilterChainMap filterChainMap) {
        this.filterChainMap = filterChainMap;
    }

    public FilterChainMap getFilterChainMap() {
        return filterChainMap;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * A <code>FilterChain</code> that records whether or not {@link
     * FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} is called.<p>This
     * <code>FilterChain</code> is used by <code>FilterChainProxy</code> to determine if the next <code>Filter</code>
     * should be called or not.</p>
     */
    private static class VirtualFilterChain implements FilterChain {
        private FilterInvocation fi;
        private Filter[] additionalFilters;
        private int currentPosition = 0;

        public VirtualFilterChain(FilterInvocation filterInvocation, Filter[] additionalFilters) {
            this.fi = filterInvocation;
            this.additionalFilters = additionalFilters;
        }

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

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

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.intercept.web.FilterInvocationDefinitionSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;


/**
 * Delegates <code>Filter</code> requests to a list of Spring-managed beans.
 * As of version 2.0, you shouldn't need to explicitly configure a <tt>FilterChainProxy</tt> bean in your application
 * context unless you need very fine control over the filter chain contents. Most cases should be adequately covered
 * by the default <tt>&lt;security:http /&gt</tt> namespace configuration options.
 *
 * <p>The <code>FilterChainProxy</code> is loaded via a standard Spring {@link DelegatingFilterProxy} declaration in
 * <code>web.xml</code>. <code>FilterChainProxy</code> will then pass {@link #init(FilterConfig)}, {@link #destroy()}
 * and {@link #doFilter(ServletRequest, ServletResponse, FilterChain)} invocations through to each <code>Filter</code>
 * defined against <code>FilterChainProxy</code>.
 *
 * <p>As of version 2.0, <tt>FilterChainProxy</tt> is configured using an ordered Map of path patterns to <tt>List</tt>s
 * of <tt>Filter</tt> objects. In previous
 * versions, a {@link FilterInvocationDefinitionSource} was used. This is now deprecated in favour of namespace-based
 * configuration which provides a more robust and simplfied syntax.  The Map instance will normally be
 * created while parsing the namespace configuration, so doesn't have to be set explicitly.
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
 *
 * <p>
 * Each possible URI pattern that <code>FilterChainProxy</code> should service must be entered.
 * The first matching URI pattern for a given request will be used to define all of the
 * <code>Filter</code>s that apply to that request. NB: This means you must put most specific URI patterns at the top
 * of the list, and ensure all <code>Filter</code>s that should apply for a given URI pattern are entered against the
 * respective entry. The <code>FilterChainProxy</code> will not iterate the remainder of the URI patterns to locate
 * additional <code>Filter</code>s.
 *
 * <p><code>FilterChainProxy</code> respects normal handling of <code>Filter</code>s that elect not to call {@link
 * javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
 * javax.servlet.FilterChain)}, in that the remainder of the original or <code>FilterChainProxy</code>-declared filter
 * chain will not be called.
 *
 * <p>Note the <code>Filter</code> lifecycle mismatch between the servlet container and IoC
 * container. As described in the {@link DelegatingFilterProxy} JavaDocs, we recommend you allow the IoC
 * container to manage the lifecycle instead of the servlet container. By default the <code>DelegatingFilterProxy</code>
 * will never call this class' {@link #init(FilterConfig)} and {@link #destroy()} methods, which in turns means that
 * the corresponding methods on the filter beans managed by this class will never be called. If you do need your filters to be
 * initialized and destroyed, please set the <tt>targetFilterLifecycle</tt> initialization parameter against the
 * <code>DelegatingFilterProxy</code> to specify that servlet container lifecycle management should be used. You don't
 * need to worry about this in most cases.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 *
 * @version $Id$
 */
public class FilterChainProxy implements Filter, InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(FilterChainProxy.class);
    public static final String TOKEN_NONE = "#NONE#";

    //~ Instance fields ================================================================================================

//    private ApplicationContext applicationContext;
    /** Map of the original pattern Strings to filter chains */
    private Map<String, List<Filter>> uncompiledFilterChainMap;
    /** Compiled pattern version of the filter chain map */
    private Map<Object, List<Filter>> filterChainMap;
    private UrlMatcher matcher = new AntUrlPathMatcher();
    private boolean stripQueryStringFromUrls = true;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(uncompiledFilterChainMap, "filterChainMap must be set");
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        for (Filter filter : obtainAllDefinedFilters()) {
            if (filter != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Initializing Filter defined in ApplicationContext: '" + filter + "'");
                }

                filter.init(filterConfig);
            }
        }
    }

    public void destroy() {
        for (Filter filter : obtainAllDefinedFilters()) {
            if (filter != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Destroying Filter defined in ApplicationContext: '" + filter + "'");
                }

                filter.destroy();
            }
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);
        List<Filter> filters = getFilters(fi.getRequestUrl());

        if (filters == null || filters.size() == 0) {
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

    /**
     * Returns the first filter chain matching the supplied URL.
     *
     * @param url the request URL
     * @return an ordered array of Filters defining the filter chain
     */
    public List<Filter> getFilters(String url)  {
        if (stripQueryStringFromUrls) {
            // String query string - see SEC-953
            int firstQuestionMarkIndex = url.indexOf("?");

            if (firstQuestionMarkIndex != -1) {
                url = url.substring(0, firstQuestionMarkIndex);
            }
        }

        for (Map.Entry<Object, List<Filter>> entry : filterChainMap.entrySet()) {
            Object path = entry.getKey();

            if (matcher.requiresLowerCaseUrl()) {
                url = url.toLowerCase();

                if (logger.isDebugEnabled()) {
                    logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
                }
            }

            boolean matched = matcher.pathMatchesUrl(path, url);

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is " + path + "; matched=" + matched);
            }

            if (matched) {
                return entry.getValue();
            }
        }

        return null;
    }

    /**
     * Obtains all of the <b>unique</b><code>Filter</code> instances registered in the map of
     * filter chains.
     * <p>This is useful in ensuring a <code>Filter</code> is not initialized or destroyed twice.</p>
     *
     * @return all of the <code>Filter</code> instances in the application context which have an entry
     *         in the map (only one entry is included in the array for
     *         each <code>Filter</code> that actually exists in application context, even if a given
     *         <code>Filter</code> is defined multiples times in the filter chain map)
     */
    protected Collection<Filter> obtainAllDefinedFilters() {
        Set<Filter> allFilters = new LinkedHashSet<Filter>();

        for (List<Filter> filters : filterChainMap.values()) {
            allFilters.addAll(filters);
        }

        return allFilters;
    }

    /**
     * Sets the mapping of URL patterns to filter chains.
     *
     * The map keys should be the paths and the values should be arrays of <tt>Filter</tt> objects.
     * It's VERY important that the type of map used preserves ordering - the order in which the iterator
     * returns the entries must be the same as the order they were added to the map, otherwise you have no way
     * of guaranteeing that the most specific patterns are returned before the more general ones. So make sure
     * the Map used is an instance of <tt>LinkedHashMap</tt> or an equivalent, rather than a plain <tt>HashMap</tt>, for
     * example.
     *
     * @param filterChainMap the map of path Strings to <tt>List&lt;Filter&gt;</tt>s.
     */
    @SuppressWarnings("unchecked")
    public void setFilterChainMap(Map filterChainMap) {
        checkContents(filterChainMap);
        uncompiledFilterChainMap = new LinkedHashMap<String, List<Filter>>(filterChainMap);
        checkPathOrder();
        createCompiledMap();
    }

    @SuppressWarnings("unchecked")
    private void checkContents(Map filterChainMap) {
        for (Object key : filterChainMap.keySet()) {
            Assert.isInstanceOf(String.class, key, "Path key must be a String but found " + key);
            Object filters = filterChainMap.get(key);
            Assert.isInstanceOf(List.class, filters, "Value must be a filter list");
            // Check the contents
            Iterator filterIterator = ((List)filters).iterator();

            while (filterIterator.hasNext()) {
                Object filter = filterIterator.next();
                Assert.isInstanceOf(Filter.class, filter, "Objects in filter chain must be of type Filter. ");
            }
        }
    }

    private void checkPathOrder() {
        // Check that the universal pattern is listed at the end, if at all
        String[] paths = (String[]) uncompiledFilterChainMap.keySet().toArray(new String[0]);
        String universalMatch = matcher.getUniversalMatchPattern();

        for (int i=0; i < paths.length-1; i++) {
            if (paths[i].equals(universalMatch)) {
                throw new IllegalArgumentException("A universal match pattern " + universalMatch + " is defined " +
                        " before other patterns in the filter chain, causing them to be ignored. Please check the " +
                        "ordering in your <security:http> namespace or FilterChainProxy bean configuration");
            }
        }
    }

    private void createCompiledMap() {
        filterChainMap = new LinkedHashMap<Object, List<Filter>>(uncompiledFilterChainMap.size());

        for (String path : uncompiledFilterChainMap.keySet()) {
            filterChainMap.put(matcher.compile(path), uncompiledFilterChainMap.get(path));
        }
    }

    /**
     * Returns a copy of the underlying filter chain map. Modifications to the map contents
     * will not affect the FilterChainProxy state - to change the map call <tt>setFilterChainMap</tt>.
     *
     * @return the map of path pattern Strings to filter chain lists (with ordering guaranteed).
     */
    public Map<String, List<Filter>> getFilterChainMap() {
        return new LinkedHashMap<String, List<Filter>>(uncompiledFilterChainMap);
    }

    public void setMatcher(UrlMatcher matcher) {
        this.matcher = matcher;
    }

    public UrlMatcher getMatcher() {
        return matcher;
    }

    /**
     * If set to 'true', the query string will be stripped from the request URL before
     * attempting to find a matching filter chain. This is the default value.
     */
    public void setStripQueryStringFromUrls(boolean stripQueryStringFromUrls) {
        this.stripQueryStringFromUrls = stripQueryStringFromUrls;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("FilterChainProxy[");
        sb.append(" UrlMatcher = ").append(matcher);
        sb.append("; Filter Chains: ");
        sb.append(uncompiledFilterChainMap);
        sb.append("]");

        return sb.toString();
    }

    //~ Inner Classes ==================================================================================================

    /**
     * A <code>FilterChain</code> that records whether or not {@link
     * FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} is called.
     * <p>
     * This <code>FilterChain</code> is used by <code>FilterChainProxy</code> to determine if the next
     * <code>Filter</code> should be called or not.</p>
     */
    private static class VirtualFilterChain implements FilterChain {
        private FilterInvocation fi;
        private List<Filter> additionalFilters;
        private int currentPosition = 0;

        private VirtualFilterChain(FilterInvocation filterInvocation, List<Filter> additionalFilters) {
            this.fi = filterInvocation;
            this.additionalFilters = additionalFilters;
        }

        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (currentPosition == additionalFilters.size()) {
                if (logger.isDebugEnabled()) {
                    logger.debug(fi.getRequestUrl()
                        + " reached end of additional filter chain; proceeding with original chain");
                }

                fi.getChain().doFilter(request, response);
            } else {
                currentPosition++;

                Filter nextFilter = additionalFilters.get(currentPosition - 1);

                if (logger.isDebugEnabled()) {
                    logger.debug(fi.getRequestUrl() + " at position " + currentPosition + " of "
                        + additionalFilters.size() + " in additional filter chain; firing Filter: '"
                        + nextFilter + "'");
                }

               nextFilter.doFilter(request, response, this);
            }
        }
    }

}

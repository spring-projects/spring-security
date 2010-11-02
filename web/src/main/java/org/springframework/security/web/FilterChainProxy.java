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

package org.springframework.security.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.AntUrlPathMatcher;
import org.springframework.security.web.util.UrlMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;


/**
 * Delegates {@code Filter} requests to a list of Spring-managed filter beans.
 * As of version 2.0, you shouldn't need to explicitly configure a {@code FilterChainProxy} bean in your application
 * context unless you need very fine control over the filter chain contents. Most cases should be adequately covered
 * by the default <tt>&lt;security:http /&gt;</tt> namespace configuration options.
 *
 * <p>The <code>FilterChainProxy</code> is loaded via a standard Spring {@link DelegatingFilterProxy} declaration in
 * <code>web.xml</code>. <code>FilterChainProxy</code> will then pass {@link #init(FilterConfig)}, {@link #destroy()}
 * and {@link #doFilter(ServletRequest, ServletResponse, FilterChain)} invocations through to each <code>Filter</code>
 * defined against <code>FilterChainProxy</code>.
 *
 * <p>As of version 2.0, <tt>FilterChainProxy</tt> is configured using an ordered Map of path patterns to <tt>List</tt>s
 * of <tt>Filter</tt> objects. In previous
 * versions, a {@link FilterInvocationSecurityMetadataSource} was used. This is now deprecated in favour of namespace-based
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
 * The names "filter1", "filter2", "filter3" should be the bean names of {@code Filter} instances defined in the
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
 * javax.servlet.FilterChain)}, in that the remainder of the original or {@code FilterChainProxy}-declared filter
 * chain will not be called.
 *
 * <h3>Request Firewalling</h3>
 *
 * An {@link HttpFirewall} instance is used to validate incoming requests and create a wrapped request which provides
 * consistent path values for matching against. See {@link DefaultHttpFirewall}, for more information on the type of
 * attacks which the default implementation protects against. A custom implementation can be injected to provide
 * stricter control over the request contents or if an application needs to support certain types of request which
 * are rejected by default.
 * <p>
 * Note that this means that you must use the Spring Security filters in combination with a {@code FilterChainProxy}
 * if you want this protection. Don't define them explicitly in your {@code web.xml} file.
 * <p>
 * {@code FilterChainProxy} will use the firewall instance to obtain both request and response objects which will be
 * fed down the filter chain, so it is also possible to use this functionality to control the functionality of the
 * response. When the request has passed through the security filter chain, the {@code reset} method will be called.
 * With the default implementation this means that the original values of {@code servletPath} and {@code pathInfo} will
 * be returned thereafter, instead of the modified ones used for security pattern matching.
 *
 * <h2>Filter Lifecycle</h2>
 * <p>
 * Note the {@code Filter} lifecycle mismatch between the servlet container and IoC
 * container. As described in the {@link DelegatingFilterProxy} Javadocs, we recommend you allow the IoC
 * container to manage the lifecycle instead of the servlet container. {@code FilterChainProxy} does not invoke the
 * standard filter lifecycle methods on any filter beans that you add to the application context.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 *
 */
public class FilterChainProxy extends GenericFilterBean {
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
    private HttpFirewall firewall = new DefaultHttpFirewall();
    private FilterChainValidator filterChainValidator = new NullFilterChainValidator();

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(uncompiledFilterChainMap, "filterChainMap must be set");
        filterChainValidator.validate(this);
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        FirewalledRequest fwRequest = firewall.getFirewalledRequest((HttpServletRequest) request);
        HttpServletResponse fwResponse = firewall.getFirewalledResponse((HttpServletResponse) response);
        String url = UrlUtils.buildRequestUrl(fwRequest);

        List<Filter> filters = getFilters(url);

        if (filters == null || filters.size() == 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(url + (filters == null ? " has no matching filters" : " has an empty filter list"));
            }

            fwRequest.reset();

            chain.doFilter(fwRequest, fwResponse);

            return;
        }

        VirtualFilterChain vfc = new VirtualFilterChain(url, chain, filters);
        vfc.doFilter(fwRequest, fwResponse);
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
     * The map keys should be the paths and the values should be arrays of {@code Filter} objects.
     * It's VERY important that the type of map used preserves ordering - the order in which the iterator
     * returns the entries must be the same as the order they were added to the map, otherwise you have no way
     * of guaranteeing that the most specific patterns are returned before the more general ones. So make sure
     * the Map used is an instance of {@code LinkedHashMap} or an equivalent, rather than a plain {@code HashMap}, for
     * example.
     *
     * @param filterChainMap the map of path Strings to {@code List&lt;Filter&gt;}s.
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
     * will not affect the FilterChainProxy state - to change the map call {@code setFilterChainMap}.
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

    public void setFirewall(HttpFirewall firewall) {
        this.firewall = firewall;
    }

    /**
     * If set to 'true', the query string will be stripped from the request URL before
     * attempting to find a matching filter chain. This is the default value.
     */
    public void setStripQueryStringFromUrls(boolean stripQueryStringFromUrls) {
        this.stripQueryStringFromUrls = stripQueryStringFromUrls;
    }

    /**
     * Used (internally) to specify a validation strategy for the filters in each configured chain.
     *
     * @param filterChainValidator
     */
    public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
        this.filterChainValidator = filterChainValidator;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("FilterChainProxy[");
        sb.append(" UrlMatcher = ").append(matcher);
        sb.append("; Filter Chains: ");
        sb.append(uncompiledFilterChainMap);
        sb.append("]");

        return sb.toString();
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Internal {@code FilterChain} implementation that is used to pass a request through the additional
     * internal list of filters which match the request.
     */
    private static class VirtualFilterChain implements FilterChain {
        private final FilterChain originalChain;
        private final List<Filter> additionalFilters;
        private final String url;
        private int currentPosition = 0;

        private VirtualFilterChain(String url, FilterChain chain, List<Filter> additionalFilters) {
            this.originalChain = chain;
            this.url = url;
            this.additionalFilters = additionalFilters;
        }

        public void doFilter(final ServletRequest request, final ServletResponse response) throws IOException, ServletException {
            if (currentPosition == additionalFilters.size()) {
                if (logger.isDebugEnabled()) {
                    logger.debug(url + " reached end of additional filter chain; proceeding with original chain");
                }

                // Deactivate path stripping as we exit the security filter chain
                resetWrapper(request);

                originalChain.doFilter(request, response);
            } else {
                currentPosition++;

                Filter nextFilter = additionalFilters.get(currentPosition - 1);

                if (logger.isDebugEnabled()) {
                    logger.debug(url + " at position " + currentPosition + " of "
                        + additionalFilters.size() + " in additional filter chain; firing Filter: '"
                        + nextFilter.getClass().getSimpleName() + "'");
                }

                nextFilter.doFilter(request, response, this);
            }
        }

        private void resetWrapper(ServletRequest request) {
            while (request instanceof ServletRequestWrapper) {
                if (request instanceof FirewalledRequest) {
                    ((FirewalledRequest)request).reset();
                    break;
                }
                request = ((ServletRequestWrapper)request).getRequest();
            }
        }
    }

    public interface FilterChainValidator {
        void validate(FilterChainProxy filterChainProxy);
    }

    private class NullFilterChainValidator implements FilterChainValidator {
        public void validate(FilterChainProxy filterChainProxy) {
        }
    }

}

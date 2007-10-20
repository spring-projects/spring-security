package org.springframework.security.intercept.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.util.UrlMatcher;
import org.springframework.util.Assert;

import javax.servlet.Filter;
import java.util.*;

/**
 * Maps filter invocations to filter chains. Used to configure FilterChainProxy.
 *
 * @see org.springframework.security.util.FilterChainProxy
 *
 * @author luke
 * @version $Id$
 * @since 2.0
 */
public class FilterChainMap implements InitializingBean {
    private static final Log logger = LogFactory.getLog(FilterChainMap.class);

    private List paths = new ArrayList();
    private List compiledPaths = new ArrayList();
    private List filterChains = new ArrayList();

    private UrlMatcher matcher = new AntUrlPathMatcher();

    public FilterChainMap() {
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notEmpty(paths, "No secure URL paths defined");
    }

    public void addSecureUrl(String path, Filter[] filters) {
        Assert.hasText(path, "The Path must not be empty or null");
        Assert.notNull(filters, "The Filter array must not be null");
        paths.add(path);
        compiledPaths.add(matcher.compile(path));
        filterChains.add(filters);

        if (logger.isDebugEnabled()) {
            logger.debug("Added pattern: " + path + "; filters: " + Arrays.asList(filters));
        }
    }

    public void setUrlPathMatcher(UrlMatcher matcher) {
        this.matcher = matcher;
    }

    public UrlMatcher getMatcher() {
        return matcher;
    }

    /**
     * Returns the first filter chain matching the supplied URL.
     *
     * @param url the request URL
     * @return an ordered array of Filters defining the filter chain
     */
    public Filter[] getFilters(String url) {

        for (int i=0; i < compiledPaths.size(); i++) {
            Object path = compiledPaths.get(i);

            boolean matched = matcher.pathMatchesUrl(path, url);

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is " + paths.get(i) + "; matched=" + matched);
            }

            if (matched) {
                return (Filter[]) filterChains.get(i);
            }
        }

        return null;
    }

    /**
     * Obtains all of the <b>unique</b><code>Filter</code> instances registered in the
     * <code>FilterChainMap</code>.
     * <p>This is useful in ensuring a <code>Filter</code> is not
     * initialized or destroyed twice.</p>
     * @return all of the <code>Filter</code> instances which have an entry
     *         in the <code>FilterChainMap</code> (only one entry is included in the array for
     *         each <code>Filter</code> instance, even if a given
     *         <code>Filter</code> is used multiples times by the <code>FilterChainMap</code>)
     */
    public Filter[] getAllDefinedFilters() {
        Set allFilters = new HashSet();

        Iterator it = filterChains.iterator();
        while (it.hasNext()) {
            Filter[] filterChain = (Filter[])it.next();

            for(int i=0; i < filterChain.length; i++) {
                allFilters.add(filterChain[i]);
            }
        }

        return (Filter[]) new ArrayList(allFilters).toArray(new Filter[0]);
    }
}

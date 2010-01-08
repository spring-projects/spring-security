package org.springframework.security.web.savedrequest;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.GenericFilterBean;

/**
 * Responsible for reconstituting the saved request if one is cached and it matches the current request.
 * <p>
 * It will call {@link RequestCache#getMatchingRequest(HttpServletRequest, HttpServletResponse) getMatchingRequest}
 * on the configured <tt>RequestCache</tt>. If the method returns a value (a wrapper of the saved request), it will
 * pass this to the filter chain's <tt>doFilter</tt> method.
 * If null is returned by the cache, the original request is used and the filter has no effect.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class RequestCacheAwareFilter extends GenericFilterBean {

    private RequestCache requestCache = new HttpSessionRequestCache();

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest wrappedSavedRequest =
            requestCache.getMatchingRequest((HttpServletRequest)request, (HttpServletResponse)response);

        chain.doFilter(wrappedSavedRequest == null ? request : wrappedSavedRequest, response);
    }

    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }

}

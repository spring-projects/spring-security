package org.springframework.security.ui;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.Ordered;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.FilterChain;
import javax.servlet.ServletResponse;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.Filter;
import java.io.IOException;

/**
 * Implements Ordered interface as required by security namespace configuration and implements unused filter
 * lifecycle methods and performs casting of request and response to http versions in doFilter method.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class SpringSecurityFilter implements Filter, Ordered {
    protected final Log logger = LogFactory.getLog(this.getClass());
    
    /**
     * Does nothing. We use IoC container lifecycle services instead.
     *
     * @param filterConfig ignored
     * @throws ServletException ignored
     */
    public final void init(FilterConfig filterConfig) throws ServletException {
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     */
    public final void destroy() {
    }

    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Do we really need the checks on the types in practice ?
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        doFilterHttp((HttpServletRequest)request, (HttpServletResponse)response, chain);
    }

    protected abstract void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException;

    public String toString() {
        return getClass() + "[ order=" + getOrder() + "; ]";
    }
}
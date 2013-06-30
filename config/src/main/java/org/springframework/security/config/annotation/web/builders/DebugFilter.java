/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.builders;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.UrlUtils;

/**
 * Spring Security debugging filter.
 * <p>
 * Logs information (such as session creation) to help the user understand how requests are being handled
 * by Spring Security and provide them with other relevant information (such as when sessions are being created).
 *
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 */
class DebugFilter implements Filter {
    private static final String ALREADY_FILTERED_ATTR_NAME = DebugFilter.class.getName().concat(".FILTERED");

    private final FilterChainProxy fcp;
    private final Logger logger = new Logger();

    public DebugFilter(FilterChainProxy fcp) {
        this.fcp = fcp;
    }

    public final void doFilter(ServletRequest srvltRequest, ServletResponse srvltResponse, FilterChain filterChain)
            throws ServletException, IOException {

        if (!(srvltRequest instanceof HttpServletRequest) || !(srvltResponse instanceof HttpServletResponse)) {
            throw new ServletException("DebugFilter just supports HTTP requests");
        }
        HttpServletRequest request = (HttpServletRequest) srvltRequest;
        HttpServletResponse response = (HttpServletResponse) srvltResponse;

        List<Filter> filters = getFilters(request);
        logger.log("Request received for '" + UrlUtils.buildRequestUrl(request) + "':\n\n" +
                request + "\n\n" +
                "servletPath:" + request.getServletPath() + "\n" +
                "pathInfo:" + request.getPathInfo() + "\n\n" +
                formatFilters(filters));

        if (request.getAttribute(ALREADY_FILTERED_ATTR_NAME) == null) {
            invokeWithWrappedRequest(request, response, filterChain);
        } else {
            fcp.doFilter(request, response, filterChain);
        }
    }

    private void invokeWithWrappedRequest(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        request.setAttribute(ALREADY_FILTERED_ATTR_NAME, Boolean.TRUE);
        request = new DebugRequestWrapper(request);
        try {
            fcp.doFilter(request, response, filterChain);
        }
        finally {
            request.removeAttribute(ALREADY_FILTERED_ATTR_NAME);
        }
    }

    String formatFilters(List<Filter> filters) {
        StringBuilder sb = new StringBuilder();
        sb.append("Security filter chain: ");
        if (filters == null) {
            sb.append("no match");
        } else if (filters.isEmpty()) {
            sb.append("[] empty (bypassed by security='none') ");
        } else {
            sb.append("[\n");
            for (Filter f : filters) {
                sb.append("  ").append(f.getClass().getSimpleName()).append("\n");
            }
            sb.append("]");
        }

        return sb.toString();
    }

    private List<Filter> getFilters(HttpServletRequest request)  {
        for (SecurityFilterChain chain : fcp.getFilterChains()) {
            if (chain.matches(request)) {
                return chain.getFilters();
            }
        }

        return null;
    }

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void destroy() {
    }
}

class DebugRequestWrapper extends HttpServletRequestWrapper {
    private static final Logger logger = new Logger();

    public DebugRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public HttpSession getSession() {
        boolean sessionExists = super.getSession(false) != null;
        HttpSession session = super.getSession();

        if (!sessionExists) {
            logger.log("New HTTP session created: " + session.getId(), true);
        }

        return session;
    }

    @Override
    public HttpSession getSession(boolean create) {
        if (!create) {
            return super.getSession(create);
        }
        return getSession();
    }
}

/**
 * Controls output for the Spring Security debug feature.
 *
 * @author Luke Taylor
 * @since 3.1
 */
final class Logger {
    final static Log logger = LogFactory.getLog("Spring Security Debugger");

    void log(String message) {
        log(message, false);
    }

    void log(String message, boolean dumpStack) {
        StringBuilder output = new StringBuilder(256);
        output.append("\n\n************************************************************\n\n");
        output.append(message).append("\n");

        if (dumpStack) {
            StringWriter os = new StringWriter();
            new Exception().printStackTrace(new PrintWriter(os));
            StringBuffer buffer = os.getBuffer();
            // Remove the exception in case it scares people.
            int start = buffer.indexOf("java.lang.Exception");
            buffer.replace(start, start + 19, "");
            output.append("\nCall stack: \n").append(os.toString());
        }

        output.append("\n\n************************************************************\n\n");

        logger.info(output.toString());
    }
}

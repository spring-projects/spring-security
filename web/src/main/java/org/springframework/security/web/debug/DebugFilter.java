package org.springframework.security.web.debug;

import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.UrlUtils;

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
import java.io.IOException;
import java.util.*;

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
public final class DebugFilter implements Filter {
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
        logger.info("Request received for '" + UrlUtils.buildRequestUrl(request) + "':\n\n" +
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
            logger.info("New HTTP session created: " + session.getId(), true);
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



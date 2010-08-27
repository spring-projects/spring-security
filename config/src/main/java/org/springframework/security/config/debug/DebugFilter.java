package org.springframework.security.config.debug;

import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Spring Security debugging filter.
 * <p>
 * Logs information (such as session creation) to help the user understand how requests are being handled
 * by Spring Security and provide them with other relevant information (such as when sessions are being created).
 *
 *
 * @author Luke Taylor
 * @since 3.1
 */
class DebugFilter extends OncePerRequestFilter {
    private final FilterChainProxy fcp;
    private final Map<RequestMatcher, List<Filter>> filterChainMap;
    private final Logger logger = new Logger();

    public DebugFilter(FilterChainProxy fcp) {
        this.fcp = fcp;
        this.filterChainMap = fcp.getFilterChainMap();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        List<Filter> filters = getFilters(request);
        logger.log("Request received for '" + UrlUtils.buildRequestUrl(request) + "':\n\n" +
                request + "\n\n" +
                formatFilters(filters));

        fcp.doFilter(new DebugRequestWrapper(request), response, filterChain);
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
        for (Map.Entry<RequestMatcher, List<Filter>> entry : filterChainMap.entrySet()) {
            RequestMatcher matcher = entry.getKey();

            if (matcher.matches(request)) {
                return entry.getValue();
            }
        }

        return null;
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



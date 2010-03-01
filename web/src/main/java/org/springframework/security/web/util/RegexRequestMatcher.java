package org.springframework.security.web.util;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
public final class RegexRequestMatcher implements RequestMatcher {
    private final static Log logger = LogFactory.getLog(RegexRequestMatcher.class);

    private final Pattern pattern;
    private final HttpMethod httpMethod;

    public RegexRequestMatcher(String pattern, String httpMethod) {
        this(pattern, httpMethod, false);
    }

    public RegexRequestMatcher(String pattern, String httpMethod, boolean caseInsensitive) {
        if (caseInsensitive) {
            this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        } else {
            this.pattern = Pattern.compile(pattern);
        }
        this.httpMethod = StringUtils.hasText(httpMethod) ? HttpMethod.valueOf(httpMethod) : null;
    }

    public boolean matches(HttpServletRequest request) {
        if (httpMethod != null && httpMethod != HttpMethod.valueOf(request.getMethod())) {
            return false;
        }

        String url = request.getServletPath();
        String pathInfo = request.getPathInfo();
        String query = request.getQueryString();

        if (pathInfo != null || query != null) {
            StringBuilder sb = new StringBuilder(url);

            if (pathInfo != null) {
                sb.append(pathInfo);
            }

            if (query != null) {
                sb.append(query);
            }
            url = sb.toString();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Checking match of request : '" + url + "'; against '" + pattern + "'");
        }

        return pattern.matcher(url).matches();
    }
}

package org.springframework.security.web.headers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Contract for a factory that creates {@code Header} instances.
 *
 * @author Marten Deinum
 * @since 3.2
 * @see HeadersFilter
 */
public interface HeaderFactory {

    /**
     * Create a {@code Header} instance.
     *
     * @param request the request
     * @param response the response
     * @return the created Header or <code>null</code>
     */
    Header create(HttpServletRequest request, HttpServletResponse response);
}

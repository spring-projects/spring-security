package org.springframework.security.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Encapsulates the redirection logic for all classes in the framework which perform redirects.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface RedirectStrategy {

    /**
     * Performs a redirect to the supplied URL
     * @param request the current request
     * @param response the response to redirect
     * @param url the target URL to redirect to, for example "/login"
     */
    void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException;
}

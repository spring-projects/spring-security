package org.springframework.security.web.savedrequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Null implementation of <tt>RequestCache</tt>.
 * Typically used when creation of a session is not desired.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class NullRequestCache implements RequestCache {

    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

    public void removeRequest(HttpServletRequest request, HttpServletResponse response) {

    }

    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
    }

    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

}

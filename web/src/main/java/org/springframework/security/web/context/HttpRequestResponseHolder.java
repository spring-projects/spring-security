package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Used to pass the incoming request to {@link SecurityContextRepository#loadContext(HttpRequestResponseHolder)},
 * allowing the method to swap the request for a wrapped version, as well as returning the <tt>SecurityContext</tt>
 * value.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class HttpRequestResponseHolder {
    HttpServletRequest request;
    HttpServletResponse response;

    public HttpRequestResponseHolder(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    HttpServletRequest getRequest() {
        return request;
    }

    void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    HttpServletResponse getResponse() {
        return response;
    }

    void setResponse(HttpServletResponse response) {
        this.response = response;
    }
}

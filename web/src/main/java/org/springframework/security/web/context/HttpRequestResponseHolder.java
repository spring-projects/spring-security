package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Used to pass the incoming request to {@link SecurityContextRepository#loadContext(HttpRequestResponseHolder)},
 * allowing the method to swap the request for a wrapped version, as well as returning the <tt>SecurityContext</tt>
 * value.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class HttpRequestResponseHolder {
    private HttpServletRequest request;
    private HttpServletResponse response;

    public HttpRequestResponseHolder(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public void setResponse(HttpServletResponse response) {
        this.response = response;
    }
}

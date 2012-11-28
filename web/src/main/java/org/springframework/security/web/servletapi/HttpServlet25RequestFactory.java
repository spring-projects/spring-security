package org.springframework.security.web.servletapi;

import javax.servlet.http.HttpServletRequest;

final class HttpServlet25RequestFactory implements HttpServletRequestFactory {
    private final String rolePrefix;

    HttpServlet25RequestFactory(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    public HttpServletRequest create(HttpServletRequest request) {
        return new SecurityContextHolderAwareRequestWrapper(request, rolePrefix) ;
    }
}

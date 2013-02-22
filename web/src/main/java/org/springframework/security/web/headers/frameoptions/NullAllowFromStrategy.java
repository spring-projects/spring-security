package org.springframework.security.web.headers.frameoptions;

import javax.servlet.http.HttpServletRequest;

/**
 * Created with IntelliJ IDEA.
 * User: marten
 * Date: 30-01-13
 * Time: 11:06
 * To change this template use File | Settings | File Templates.
 */
public class NullAllowFromStrategy implements AllowFromStrategy {
    @Override
    public String apply(HttpServletRequest request) {
        return null;
    }
}

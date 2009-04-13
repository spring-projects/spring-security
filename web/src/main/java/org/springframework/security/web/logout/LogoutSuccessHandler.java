package org.springframework.security.web.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * Strategy that is called after a successful logout by the {@link LogoutFilter}, to handle redirection or
 * forwarding to the appropriate destination.
 * <p>
 * Note that the interface is almost the same as {@link LogoutHandler} but may raise an exception.
 * <tt>LogoutHandler</tt> implementations expect to be invoked to perform necessary cleanup, so should not throw
 * exceptions.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public interface LogoutSuccessHandler {

    void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException;

}

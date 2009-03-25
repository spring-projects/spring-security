package org.springframework.security.ui.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.Authentication;
import org.springframework.security.ui.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.ui.LogoutSuccessHandler;

/**
 * Handles the navigation on logout by delegating to the {@link AbstractAuthenticationTargetUrlRequestHandler}
 * base class logic.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class SimpleUrlLogoutSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler
        implements LogoutSuccessHandler {

    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        super.handle(request, response, authentication);
    }

}

package org.springframework.security.ui;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.Authentication;

/**
 * Strategy used to handle a successful user authentication.
 * <p>
 * Implementations can do whatever they want but typical behaviour would be to control the navigation to the
 * subsequent destination (using a redirect or a forward). For example, after a user has logged in by submitting a
 * login form, the application needs to decide where they should be redirected to afterwards
 * (see {@link AbstractProcessingFilter} and subclasses). Other logic may also be included if required.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 * @see
 */
public interface AuthenticationSuccessHandler {

    /**
     * Called when a user has been successfully authenticated.
     *
     * @param request the request which caused the successful authentication
     * @param response the response
     * @param authentication the <tt>Authentication</tt> object which was created during the authentication process.
     */
    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException;

}

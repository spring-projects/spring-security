package org.springframework.security.ui;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.AuthenticationException;
import org.springframework.security.CredentialsExpiredException;

/**
 * Strategy used to handle a failed authentication attempt.
 * <p>
 * Typical behaviour might be to redirect the user to the authentication page (in the case of a form login) to
 * allow them to try again. More sophisticated logic might be implemented depending on the type of the exception.
 * For example, a {@link CredentialsExpiredException} might cause a redirect to a web controller which allowed the
 * user to change their password.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public interface AuthenticationFailureHandler {

    /**
     * Called when an authentication attempt fails.
     * @param request the request during which the authentication attempt occurred.
     * @param response the response.
     * @param exception the exception which was thrown to reject the authentication request.
     */
    void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException;
}

package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * <tt>AuthenticationSuccessHandler</tt> which can be configured with a default URL which users should be
 * sent to upon successful authentication.
 * <p>
 * The logic used is that of the {@link AbstractAuthenticationTargetUrlRequestHandler parent class}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class SimpleUrlAuthenticationSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler implements AuthenticationSuccessHandler {

    public SimpleUrlAuthenticationSuccessHandler() {
    }

    /**
     * Constructor which sets the <tt>defaultTargetUrl</tt> property of the base class.
     * @param defaultTargetUrl the URL to which the user should be redirected on successful authentication.
     */
    public SimpleUrlAuthenticationSuccessHandler(String defaultTargetUrl) {
        setDefaultTargetUrl(defaultTargetUrl);
    }

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        handle(request, response, authentication);
    }
}

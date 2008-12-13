package org.springframework.security.ui;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.AuthenticationException;
import org.springframework.security.util.RedirectUtils;

/**
 * Uses the internal map of exceptions types to URLs to determine the destination on authentication failure. The keys
 * are the full exception class names.
 * <p>
 * If a match isn't found, falls back to the behaviour of the parent class,
 * {@link SimpleUrlAuthenticationFailureHandler}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class ExceptionMappingAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private Map<String, String> failureUrlMap = new HashMap<String, String>();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        String url = failureUrlMap.get(exception.getClass().getName());

        if (url != null) {
            RedirectUtils.sendRedirect(request, response, url, isUseRelativeContext());
        } else {
            super.onAuthenticationFailure(request, response, exception);
        }
    }


}

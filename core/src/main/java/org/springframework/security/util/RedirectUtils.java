package org.springframework.security.util;

import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.logout.LogoutFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class RedirectUtils {
    //~ Constructors ===================================================================================================

    private RedirectUtils() {
    }

    //~ Methods ========================================================================================================

    /**
     * Encapsulates the redirect logic used in classes like {@link AbstractProcessingFilter} and {@link LogoutFilter}.
     *
     * @param request the incoming request
     * @param response the response to redirect
     * @param url the target url to redirect to
     * @param useRelativeContext if true, causes any redirection URLs to be calculated minus the protocol
     * and context path.
     *
     * @see AbstractProcessingFilter#setUseRelativeContext(boolean)
     */
    public static final void sendRedirect(HttpServletRequest request,
                                          HttpServletResponse response,
                                          String url,
                                          boolean useRelativeContext) throws IOException {
        String finalUrl;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            if (useRelativeContext) {
                finalUrl = url;
            }
            else {
                finalUrl = request.getContextPath() + url;
            }
        }
        else if (useRelativeContext) {
            // Calculate the relative URL from the fully qualifed URL, minus the protocol and base context.
            int len = request.getContextPath().length();
            int index = url.indexOf(request.getContextPath()) + len;
            finalUrl = url.substring(index);

            if (finalUrl.length() > 1 && finalUrl.charAt(0) == '/') {
                finalUrl = finalUrl.substring(1);
            }
        }
        else {
            finalUrl = url;
        }

        response.sendRedirect(response.encodeRedirectURL(finalUrl));
    }
}

package org.springframework.security.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Simple implementation of <tt>RedirectStrategy</tt> which is the default used throughout the framework.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultRedirectStrategy implements RedirectStrategy {
    protected final Log logger = LogFactory.getLog(getClass());

    private boolean contextRelative;

    /**
     * Redirects the response to the supplied URL.
     * <p>
     * If <tt>contextRelative</tt> is set, the redirect value will be the value after the request context path. Note
     * that this will result in the loss of protocol information (HTTP or HTTPS), so will cause problems if a
     * redirect is being performed to change to HTTPS, for example.
     */
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        String finalUrl;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            if (contextRelative) {
                finalUrl = url;
            }
            else {
                finalUrl = request.getContextPath() + url;
            }
        }
        else if (contextRelative) {
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

        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to '" + finalUrl + "'");
        }

        response.sendRedirect(response.encodeRedirectURL(finalUrl));
    }

    /**
     * If <tt>true</tt>, causes any redirection URLs to be calculated minus the protocol
     * and context path (defaults to <tt>false</tt>).
     */
    public void setContextRelative(boolean useRelativeContext) {
        this.contextRelative = useRelativeContext;
    }

}

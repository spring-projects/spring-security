package org.springframework.security.ui;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.AuthenticationException;
import org.springframework.security.web.util.RedirectUtils;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

/**
 * <tt>AuthenticationFailureHandler</tt> which performs a redirect to the value of the {@link #setDefaultFailureUrl
 * defaultFailureUrl} property when the <tt>onAuthenticationFailure</tt> method is called.
 * If the property has not been set it will send a 401 response to the client, with the error message from the
 * <tt>AuthenticationException</tt> which caused the failure.
 * <p>
 * If the <tt>forwardToDestination</tt> parameter is set, a <tt>RequestDispatcher.forward</tt> call will be made to
 * the destination instead of a redirect.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class SimpleUrlAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private String defaultFailureUrl;
    private boolean forwardToDestination = false;
    private boolean useRelativeContext = false;

    public SimpleUrlAuthenticationFailureHandler() {
    }

    public SimpleUrlAuthenticationFailureHandler(String defaultFailureUrl) {
        setDefaultFailureUrl(defaultFailureUrl);
    }

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        if (defaultFailureUrl == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed: " + exception.getMessage());
        } else {
            if (forwardToDestination) {
                request.getRequestDispatcher(defaultFailureUrl).forward(request, response);
            } else {
                RedirectUtils.sendRedirect(request, response, defaultFailureUrl, useRelativeContext);
            }
        }
    }

    /**
     * The URL which will be used as the failure destination.
     *
     * @param defaultFailureUrl the failure URL, for example "/loginFailed.jsp".
     */
    public void setDefaultFailureUrl(String defaultFailureUrl) {
        Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultFailureUrl));
        this.defaultFailureUrl = defaultFailureUrl;
    }

    protected boolean isUseForward() {
        return forwardToDestination;
    }

    /**
     * If set to <tt>true</tt>, performs a forward to the failure destination URL instead of a redirect. Defaults to
     * <tt>false</tt>.
     */
    public void setUseForward(boolean forwardToDestination) {
        this.forwardToDestination = forwardToDestination;
    }

    protected boolean isUseRelativeContext() {
        return useRelativeContext;
    }

    /**
     * If true, causes any redirection URLs to be calculated minus the protocol
     * and context path (defaults to false).
     */
    public void setUseRelativeContext(boolean useRelativeContext) {
        this.useRelativeContext = useRelativeContext;
    }

}

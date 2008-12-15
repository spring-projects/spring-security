package org.springframework.security.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.Authentication;
import org.springframework.security.ui.savedrequest.SavedRequest;
import org.springframework.security.util.RedirectUtils;
import org.springframework.security.wrapper.SavedRequestAwareWrapper;
import org.springframework.util.StringUtils;

/**
 * Decides on the redirect destination following a successful authentication, based on the following
 * configuration options:
 *
 * <ul>
 * <li>
 * If the <tt>alwaysUseDefaultTargetUrl</tt> property is set to true, the <tt>defaultTargetUrl</tt>
 * will be used for the destination. Any <tt>SavedRequest</tt> stored in the session will be
 * removed.
 * </li>
 * <li>
 * If the <tt>targetUrlParameter</tt> has been set on the request, the value will be used as the destination.
 * Any <tt>SavedRequest</tt> will again be removed.
 * </li>
 * <li>
 * If a {@link SavedRequest} is found in the session (as set by the {@link ExceptionTranslationFilter} to record
 * the original destination before the authentication process commenced), a redirect will be performed to the
 * Url of that original destination. The <tt>SavedRequest</tt> object will remain in the session and be picked up
 * when the redirected request is received (See {@link SavedRequestAwareWrapper}).
 * </li>
 * <li>
 * Fall back to the <tt>defaultTargetUrl</tt>
 * </li>
 * </ul>
 *
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class SavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws ServletException, IOException {
        SavedRequest savedRequest = getSavedRequest(request);

        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        if (isAlwaysUseDefaultTargetUrl() || StringUtils.hasText(request.getParameter(targetUrlParameter))) {
            removeSavedRequest(request);
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        // Use the SavedRequest URL
        String targetUrl = savedRequest.getFullRequestUrl();
        logger.debug("Redirecting to SavedRequest Url: " + targetUrl);
        RedirectUtils.sendRedirect(request, response, targetUrl, useRelativeContext);
    }

    private SavedRequest getSavedRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            return (SavedRequest) session.getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);
        }

        return null;
    }

    private void removeSavedRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            logger.debug("Removing SavedRequest from session if present");
            session.removeAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);
        }
    }
}

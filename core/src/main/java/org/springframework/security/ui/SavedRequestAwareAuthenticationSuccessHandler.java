package org.springframework.security.ui;

import java.io.IOException;

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
 * An authentication success strategy which can make use of the {@link SavedRequest} which may have been stored in
 * the session by the {@link ExceptionTranslationFilter}. When such a request is intercepted and requires authentication,
 * the request data is stored to record the original destination before the authentication process commenced, and to
 * allow the request to be reconstructed when a redirect to the same URL occurs. This class is responsible for
 * performing the redirect to the original URL if appropriate.
 * <p>
 * Following a successful authentication, it decides on the redirect destination, based on the following scenarios:
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
 * If no <tt>SavedRequest</tt> is found in the session, it will delegate to the base class.
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

        if (isAlwaysUseDefaultTargetUrl() || StringUtils.hasText(request.getParameter(getTargetUrlParameter()))) {
            removeSavedRequest(request);
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        // Use the SavedRequest URL
        String targetUrl = savedRequest.getFullRequestUrl();
        logger.debug("Redirecting to SavedRequest Url: " + targetUrl);
        RedirectUtils.sendRedirect(request, response, targetUrl, isUseRelativeContext());
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

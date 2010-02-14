package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.util.StringUtils;

/**
 * An authentication success strategy which can make use of the {@link DefaultSavedRequest} which may have been stored in
 * the session by the {@link ExceptionTranslationFilter}. When such a request is intercepted and requires authentication,
 * the request data is stored to record the original destination before the authentication process commenced, and to
 * allow the request to be reconstructed when a redirect to the same URL occurs. This class is responsible for
 * performing the redirect to the original URL if appropriate.
 * <p>
 * Following a successful authentication, it decides on the redirect destination, based on the following scenarios:
 * <ul>
 * <li>
 * If the <tt>alwaysUseDefaultTargetUrl</tt> property is set to true, the <tt>defaultTargetUrl</tt>
 * will be used for the destination. Any <tt>DefaultSavedRequest</tt> stored in the session will be
 * removed.
 * </li>
 * <li>
 * If the <tt>targetUrlParameter</tt> has been set on the request, the value will be used as the destination.
 * Any <tt>DefaultSavedRequest</tt> will again be removed.
 * </li>
 * <li>
 * If a {@link DefaultSavedRequest} is found in the <tt>RequestCache</tt> (as set by the {@link ExceptionTranslationFilter} to
 * record the original destination before the authentication process commenced), a redirect will be performed to the
 * Url of that original destination. The <tt>DefaultSavedRequest</tt> object will remain cached and be picked up
 * when the redirected request is received
 * (See {@link org.springframework.security.web.savedrequest.SavedRequestAwareWrapper SavedRequestAwareWrapper}).
 * </li>
 * <li>
 * If no <tt>DefaultSavedRequest</tt> is found, it will delegate to the base class.
 * </li>
 * </ul>
 *
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    protected final Log logger = LogFactory.getLog(this.getClass());

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws ServletException, IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        if (isAlwaysUseDefaultTargetUrl() || StringUtils.hasText(request.getParameter(getTargetUrlParameter()))) {
            requestCache.removeRequest(request, response);
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        // Use the DefaultSavedRequest URL
        String targetUrl = savedRequest.getRedirectUrl();
        logger.debug("Redirecting to DefaultSavedRequest Url: " + targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
}

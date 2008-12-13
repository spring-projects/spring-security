package org.springframework.security.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.ui.savedrequest.SavedRequest;
import org.springframework.security.util.RedirectUtils;
import org.springframework.security.wrapper.SavedRequestAwareWrapper;
import org.springframework.util.Assert;
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
public class SavedRequestAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    public static String DEFAULT_TARGET_PARAMETER = "spring-security-redirect";

    protected final Log logger = LogFactory.getLog(this.getClass());

    /* SEC-213 */
    private String targetUrlParameter = DEFAULT_TARGET_PARAMETER;

    /**
     * If <code>true</code>, will only use <code>SavedRequest</code> to determine the target URL on successful
     * authentication if the request that caused the authentication request was a GET.
     * It will then return null for a POST/PUT request.
     * Defaults to false.
     */
    private boolean justUseSavedRequestOnGet = false;

    private String defaultTargetUrl = "/";

    /**
     * If <code>true</code>, will always redirect to the value of
     * {@link #getDefaultTargetUrl} upon successful authentication, irrespective
     * of the page that caused the authentication request (defaults to
     * <code>false</code>).
     */
    private boolean alwaysUseDefaultTargetUrl = false;

    private boolean useRelativeContext = false;

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws ServletException, IOException {

        if (alwaysUseDefaultTargetUrl) {
            removeSavedRequest(request);
            RedirectUtils.sendRedirect(request, response, defaultTargetUrl, useRelativeContext);
            return;
        }

        // Check for the parameter and use that if available
        String targetUrl = request.getParameter(targetUrlParameter);

        if (StringUtils.hasText(targetUrl)) {
            try {
                targetUrl = URLDecoder.decode(targetUrl, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("UTF-8 not supported. Shouldn't be possible");
            }

            logger.debug("Found targetUrlParameter in request. Redirecting to: " + targetUrl);

            removeSavedRequest(request);
            RedirectUtils.sendRedirect(request, response, targetUrl, useRelativeContext);

            return;
        }

        // Try the SavedRequest URL
        SavedRequest savedRequest = getSavedRequest(request);

        if (savedRequest != null) {
            if (!justUseSavedRequestOnGet || savedRequest.getMethod().equals("GET")) {
                targetUrl = savedRequest.getFullRequestUrl();
                logger.debug("Redirecting to SavedRequest Url: " + targetUrl);
            } else {
                removeSavedRequest(request);
            }
        }

        if (targetUrl == null) {
            targetUrl = defaultTargetUrl;
            logger.debug("Redirecting to default Url: " + targetUrl);
        }

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

    /**
     * Supplies the default target Url that will be used if no saved request is found or the
     * <tt>alwaysUseDefaultTargetUrl</tt> property is set to true. If not set, defaults to <tt>/</tt>.
     *
     * @return the defaultTargetUrl property
     */
    protected String getDefaultTargetUrl() {
        return defaultTargetUrl;
    }

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the
     * <tt>alwaysUseDefaultTargetUrl</tt> property is set to true. If not set, defaults to <tt>/</tt>. It
     * will be treated as relative to the web-app's context path, and should include the leading <code>/</code>.
     * Alternatively, inclusion of a scheme name (such as "http://" or "https://") as the prefix will denote a
     * fully-qualified URL and this is also supported.
     *
     * @param defaultTargetUrl
     */
    public void setDefaultTargetUrl(String defaultTargetUrl) {
        Assert.isTrue(defaultTargetUrl.startsWith("/") | defaultTargetUrl.startsWith("http"),
                "defaultTarget must start with '/' or with 'http(s)'");
        this.defaultTargetUrl = defaultTargetUrl;
    }

    /**
     * If <code>true</code>, will always redirect to the value of <tt>defaultTargetUrl</tt>
     * (defaults to <code>false</code>).
     */
    public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
        this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
    }

    boolean isAlwaysUseDefaultTargetUrl() {
        return alwaysUseDefaultTargetUrl;
    }

    /**
     * @return <code>true</code> if just GET request will be used
     * to determine target URLs, <code>false</code> otherwise.
     */
    protected boolean isJustUseSavedRequestOnGet() {
        return justUseSavedRequestOnGet;
    }

    /**
     * @param justUseSavedRequestOnGet set to <code>true</code> if
     * just GET request will be used to determine target URLs,
     * <code>false</code> otherwise.
     */
    public void setJustUseSavedRequestOnGet(boolean justUseSavedRequestOnGet) {
        this.justUseSavedRequestOnGet = justUseSavedRequestOnGet;
    }

    /**
     * Before checking the SavedRequest, the current request will be checked for this parameter
     * and the value used as the target URL if resent.
     *
     *  @param targetUrlParameter the name of the parameter containing the encoded target URL. Defaults
     *  to "redirect".
     */
    public void setTargetUrlParameter(String targetUrlParameter) {
        Assert.hasText("targetUrlParamete canot be null or empty");
        this.targetUrlParameter = targetUrlParameter;
    }

    /**
     * If <tt>true</tt>, causes any redirection URLs to be calculated minus the protocol
     * and context path (defaults to <tt>false</tt>).
     */
    public void setUseRelativeContext(boolean useRelativeContext) {
        this.useRelativeContext = useRelativeContext;
    }
}

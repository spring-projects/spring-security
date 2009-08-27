package org.springframework.security.web.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Base class containing the logic used by strategies which handle redirection to a URL and
 * are passed an <tt>Authentication</tt> object as part of the contract.
 * See {@link AuthenticationSuccessHandler} and
 * {@link org.springframework.security.web.authentication.logout.LogoutSuccessHandler LogoutSuccessHandler}, for example.
 * <p>
 * Uses the following logic sequence to determine how it should handle the forward/redirect
 * <ul>
 * <li>
 * If the <tt>alwaysUseDefaultTargetUrl</tt> property is set to true, the <tt>defaultTargetUrl</tt> property
 * will be used for the destination.
 * </li>
 * <li>
 * If a parameter matching the <tt>targetUrlParameter</tt> has been set on the request, the value will be used as
 * the destination.
 * </li>
 * <li>
 * If the <tt>useReferer</tt> property is set, the "Referer" HTTP header value will be used, if present.
 * </li>
 * <li>
 * As a fallback option, the <tt>defaultTargetUrl</tt> value will be used.
 * </li>
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public abstract class AbstractAuthenticationTargetUrlRequestHandler {

    public static String DEFAULT_TARGET_PARAMETER = "spring-security-redirect";
    protected final Log logger = LogFactory.getLog(this.getClass());
    private String targetUrlParameter = DEFAULT_TARGET_PARAMETER;
    private String defaultTargetUrl = "/";
    private boolean alwaysUseDefaultTargetUrl = false;
    private boolean useReferer = false;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    protected AbstractAuthenticationTargetUrlRequestHandler() {
    }

    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response);

        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    private String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        if (isAlwaysUseDefaultTargetUrl()) {
            return defaultTargetUrl;
        }

        // Check for the parameter and use that if available
        String targetUrl = request.getParameter(targetUrlParameter);

        if (StringUtils.hasText(targetUrl)) {
            try {
                targetUrl = URLDecoder.decode(targetUrl, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("UTF-8 not supported. Shouldn't be possible");
            }

            logger.debug("Found targetUrlParameter in request: " + targetUrl);

            return targetUrl;
        }

        if (useReferer && !StringUtils.hasLength(targetUrl)) {
            targetUrl = request.getHeader("Referer");
            logger.debug("Using Referer header: " + targetUrl);
        }

        if (!StringUtils.hasText(targetUrl)) {
            targetUrl = defaultTargetUrl;
            logger.debug("Using default Url: " + targetUrl);
        }

        return targetUrl;
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
        Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultTargetUrl),
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

    protected boolean isAlwaysUseDefaultTargetUrl() {
        return alwaysUseDefaultTargetUrl;
    }

    /**
     * The current request will be checked for this parameter before and the value used as the target URL if resent.
     *
     *  @param targetUrlParameter the name of the parameter containing the encoded target URL. Defaults
     *  to "redirect".
     */
    public void setTargetUrlParameter(String targetUrlParameter) {
        Assert.hasText("targetUrlParameter canot be null or empty");
        this.targetUrlParameter = targetUrlParameter;
    }

    protected String getTargetUrlParameter() {
        return targetUrlParameter;
    }

    /**
     * Allows overriding of the behaviour when redirecting to a target URL.
     */
    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }

    /**
     * If set to <tt>true</tt> the <tt>Referer</tt> header will be used (if available). Defaults to <tt>false</tt>.
     */
    public void setUseReferer(boolean useReferer) {
        this.useReferer = useReferer;
    }
}

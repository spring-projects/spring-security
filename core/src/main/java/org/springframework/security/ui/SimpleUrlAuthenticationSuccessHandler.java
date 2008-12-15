package org.springframework.security.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.util.RedirectUtils;
import org.springframework.security.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class SimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    public static String DEFAULT_TARGET_PARAMETER = "spring-security-redirect";
    protected final Log logger = LogFactory.getLog(this.getClass());
    protected String targetUrlParameter = DEFAULT_TARGET_PARAMETER;
    protected String defaultTargetUrl = "/";
    protected boolean alwaysUseDefaultTargetUrl = false;
    protected boolean useRelativeContext = false;

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        if (isAlwaysUseDefaultTargetUrl()) {
            RedirectUtils.sendRedirect(request, response, getDefaultTargetUrl(), useRelativeContext);
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

            RedirectUtils.sendRedirect(request, response, targetUrl, useRelativeContext);

            return;
        }

        if (targetUrl == null) {
            targetUrl = getDefaultTargetUrl();
            logger.debug("Redirecting to default Url: " + targetUrl);
        }

        RedirectUtils.sendRedirect(request, response, targetUrl, useRelativeContext);
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

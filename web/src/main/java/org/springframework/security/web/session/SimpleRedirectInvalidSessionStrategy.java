package org.springframework.security.web.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Performs a redirect to a fixed URL when an invalid requested session is detected by the {@code SessionManagementFilter}.
 *
 * @author Luke Taylor
 */
public final class SimpleRedirectInvalidSessionStrategy implements InvalidSessionStrategy {
    private final Log logger = LogFactory.getLog(getClass());
    private final String destinationUrl;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private boolean createNewSession = true;

    public SimpleRedirectInvalidSessionStrategy(String invalidSessionUrl) {
        Assert.isTrue(UrlUtils.isValidRedirectUrl(invalidSessionUrl), "url must start with '/' or with 'http(s)'");
        this.destinationUrl = invalidSessionUrl;
    }

    public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response) throws IOException {
        logger.debug("Starting new session (if required) and redirecting to '" + destinationUrl + "'");
        if (createNewSession) {
            request.getSession();
        }
        redirectStrategy.sendRedirect(request, response, destinationUrl);
    }

    /**
     * Determines whether a new session should be created before redirecting (to avoid possible looping issues where
     * the same session ID is sent with the redirected request). Alternatively, ensure that the configured URL
     * does not pass through the {@code SessionManagementFilter}.
     *
     * @param createNewSession defaults to {@code true}.
     */
    public void setCreateNewSession(boolean createNewSession) {
        this.createNewSession = createNewSession;
    }
}

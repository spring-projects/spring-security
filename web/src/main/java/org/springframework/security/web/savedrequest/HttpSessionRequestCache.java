package org.springframework.security.web.savedrequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;

/**
 * <tt>RequestCache</tt> which stores the SavedRequest in the HttpSession.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class HttpSessionRequestCache implements RequestCache {
    protected final Log logger = LogFactory.getLog(this.getClass());

    private PortResolver portResolver = new PortResolverImpl();
    private boolean createSessionAllowed = true;
    private boolean justUseSavedRequestOnGet;

    /**
     * Stores the current request, provided the configuration properties allow it.
     */
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (!justUseSavedRequestOnGet || "GET".equals(request.getMethod())) {
            SavedRequest savedRequest = new SavedRequest(request, portResolver);

            if (createSessionAllowed || request.getSession(false) != null) {
                // Store the HTTP request itself. Used by AbstractAuthenticationProcessingFilter
                // for redirection after successful authentication (SEC-29)
                request.getSession().setAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest);
                logger.debug("SavedRequest added to Session: " + savedRequest);
            }
        }

    }

    public SavedRequest getRequest(HttpServletRequest currentRequest, HttpServletResponse response) {
        HttpSession session = currentRequest.getSession(false);

        if (session != null) {
            return (SavedRequest) session.getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);
        }

        return null;
    }

    public void removeRequest(HttpServletRequest currentRequest, HttpServletResponse response) {
        HttpSession session = currentRequest.getSession(false);

        if (session != null) {
            logger.debug("Removing SavedRequest from session if present");
            session.removeAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);
        }
    }

    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = getRequest(request, response);

        if (saved == null) {
            return null;
        }

        if (!saved.doesRequestMatch(request, portResolver)) {
            logger.debug("saved request doesn't match");
            return null;
        }

        removeRequest(request, response);

        return new SavedRequestAwareWrapper(saved, request);
    }

    /**
     * If <code>true</code>, will only use <code>SavedRequest</code> to determine the target URL on successful
     * authentication if the request that caused the authentication request was a GET. Defaults to false.
     */
    public void setJustUseSavedRequestOnGet(boolean justUseSavedRequestOnGet) {
        this.justUseSavedRequestOnGet = justUseSavedRequestOnGet;
    }

    /**
     * If <code>true</code>, indicates that it is permitted to store the target
     * URL and exception information in a new <code>HttpSession</code> (the default).
     * In situations where you do not wish to unnecessarily create <code>HttpSession</code>s - because the user agent
     * will know the failed URL, such as with BASIC or Digest authentication - you may wish to set this property to
     * <code>false</code>.
     */
    public void setCreateSessionAllowed(boolean createSessionAllowed) {
        this.createSessionAllowed = createSessionAllowed;
    }

    public void setPortResolver(PortResolver portResolver) {
        this.portResolver = portResolver;
    }
}

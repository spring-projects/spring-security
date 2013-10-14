package org.springframework.security.web.savedrequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.matchers.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 * {@code RequestCache} which stores the {@code SavedRequest} in the HttpSession.
 *
 * The {@link DefaultSavedRequest} class is used as the implementation.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionRequestCache implements RequestCache {
    static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
    protected final Log logger = LogFactory.getLog(this.getClass());

    private PortResolver portResolver = new PortResolverImpl();
    private boolean createSessionAllowed = true;
    private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

    /**
     * Stores the current request, provided the configuration properties allow it.
     */
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (requestMatcher.matches(request)) {
            DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, portResolver);

            if (createSessionAllowed || request.getSession(false) != null) {
                // Store the HTTP request itself. Used by AbstractAuthenticationProcessingFilter
                // for redirection after successful authentication (SEC-29)
                request.getSession().setAttribute(SAVED_REQUEST, savedRequest);
                logger.debug("DefaultSavedRequest added to Session: " + savedRequest);
            }
        } else {
            logger.debug("Request not saved as configured RequestMatcher did not match");
        }
    }

    public SavedRequest getRequest(HttpServletRequest currentRequest, HttpServletResponse response) {
        HttpSession session = currentRequest.getSession(false);

        if (session != null) {
            return (SavedRequest) session.getAttribute(SAVED_REQUEST);
        }

        return null;
    }

    public void removeRequest(HttpServletRequest currentRequest, HttpServletResponse response) {
        HttpSession session = currentRequest.getSession(false);

        if (session != null) {
            logger.debug("Removing DefaultSavedRequest from session if present");
            session.removeAttribute(SAVED_REQUEST);
        }
    }

    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        DefaultSavedRequest saved = (DefaultSavedRequest) getRequest(request, response);

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
     * Allows selective use of saved requests for a subset of requests. By default any request will be cached
     * by the {@code saveRequest} method.
     * <p>
     * If set, only matching requests will be cached.
     *
     * @param requestMatcher a request matching strategy which defines which requests should be cached.
     */
    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
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

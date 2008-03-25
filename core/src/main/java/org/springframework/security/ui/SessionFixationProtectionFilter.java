package org.springframework.security.ui;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.concurrent.SessionRegistry;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.util.SessionUtils;

/**
 * Detects that a user has been authenticated since the start of the request and starts a new session.
 * <p>
 * This is essentially a generalization of the functionality that was implemented for SEC-399. Additionally, it will
 * update the configured SessionRegistry if one is in use, thus preventing problems when used with Spring Security's
 * concurrent session control.
 * 
 * @author Martin Algesten
 * @author Luke Taylor
 * @since 2.0
 */
public class SessionFixationProtectionFilter extends SpringSecurityFilter {
    //~ Static fields/initializers =====================================================================================

    static final String FILTER_APPLIED = "__spring_security_session_fixation_filter_applied";
 
    //~ Instance fields ================================================================================================

    private SessionRegistry sessionRegistry;
    
    /**
     * Indicates that the session attributes of the session to be invalidated
     * should be migrated to the new session. Defaults to <code>true</code>.
     */
    private boolean migrateSessionAttributes = true;    

    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl(); 

    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // Session fixation isn't a problem if there's no session
        if(request.getSession(false) == null || request.getAttribute(FILTER_APPLIED) != null) {
            chain.doFilter(request, response);
            return;
        }
        
        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
                
        if (isAuthenticated()) {
            // We don't have to worry about session fixation attack if already authenticated 
            chain.doFilter(request, response);
            return;            
        }
        
        SessionFixationProtectionResponseWrapper wrapper = 
            new SessionFixationProtectionResponseWrapper(response, request);
        try {
            chain.doFilter(request, wrapper);
        } finally {
            if (!wrapper.isNewSessionStarted()) {
                startNewSessionIfRequired(request);
            }
        }
    }
    
    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        return authentication != null && !authenticationTrustResolver.isAnonymous(authentication);        
    }
    
    public void setMigrateSessionAttributes(boolean migrateSessionAttributes) {
        this.migrateSessionAttributes = migrateSessionAttributes;
    }

    public int getOrder() {
        return FilterChainOrder.SESSION_FIXATION_FILTER;
    }
    
    /**
     * Called when the an initially unauthenticated request completes or a redirect or sendError occurs.
     * <p>
     * If the user is now authenticated, a new session will be created, the session attributes copied to it (if 
     * <tt>migrateSessionAttributes</tt> is set and the sessionRegistry updated with the new session information.
     */
    protected void startNewSessionIfRequired(HttpServletRequest request) {
        if (isAuthenticated()) {
            SessionUtils.startNewSessionIfRequired(request, migrateSessionAttributes, sessionRegistry);
        }
    }
    
    /**
     * Response wrapper to handle the situation where we need to migrate the session after a redirect or sendError.
     * Similar in function to Martin Algesten's OnRedirectUpdateSessionResponseWrapper used in 
     * HttpSessionContextIntegrationFilter.  
     */
    private class SessionFixationProtectionResponseWrapper extends HttpServletResponseWrapper {
        private HttpServletRequest request;
        private boolean newSessionStarted;

        public SessionFixationProtectionResponseWrapper(HttpServletResponse response, HttpServletRequest request) {
            super(response);
            this.request = request;
        }
        
        /**
         * Makes sure a new session is created before calling the
         * superclass <code>sendError()</code>
         */
        public void sendError(int sc) throws IOException {
            startNewSession();
            super.sendError(sc);
        }

        /**
         * Makes sure a new session is created before calling the
         * superclass <code>sendError()</code>
         */
        public void sendError(int sc, String msg) throws IOException {
            startNewSession();
            super.sendError(sc, msg);
        }

        /**
         * Makes sure a new session is created before calling the
         * superclass <code>sendRedirect()</code>
         */
        public void sendRedirect(String location) throws IOException {
            startNewSession();
            super.sendRedirect(location);
        }

        /**
         * Calls <code>startNewSessionIfRequired()</code>
         */
        private void startNewSession() {
            if (newSessionStarted) {
                return;
            }
            startNewSessionIfRequired(request);
            newSessionStarted = true;
        }

        private boolean isNewSessionStarted() {
            return newSessionStarted;
        }
    }    

}

package org.springframework.security.ui;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.concurrent.SessionRegistry;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.context.SecurityContext;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.util.SessionUtils;

/**
 * Detects that a user has been authenticated since the start of the request and starts a new session.
 * <p>
 * This is essentially a generalization of the functionality that was implemented for SEC-399. 
 * Additionally, it will update the configured SessionRegistry if one is in use, thus preventing problems when used 
 * with Spring Security's concurrent session control. 
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

        HttpSession session = request.getSession();
        SecurityContext sessionSecurityContext = 
            (SecurityContext) session.getAttribute(HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY);
        
        if (sessionSecurityContext == null && isAuthenticated()) {
            // The user has been authenticated during the current request, so do the session migration
            startNewSessionIfRequired(request, response);
        }

        chain.doFilter(request, response);
    }
    
    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        return authentication != null && !authenticationTrustResolver.isAnonymous(authentication);        
    }
    
    public void setMigrateSessionAttributes(boolean migrateSessionAttributes) {
        this.migrateSessionAttributes = migrateSessionAttributes;
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
		this.sessionRegistry = sessionRegistry;
	}

	public int getOrder() {
        return FilterChainOrder.SESSION_FIXATION_FILTER;
    }
    
    /**
     * Called when the a user wasn't authenticated at the start of the request but has been during it
     * <p>
     * A new session will be created, the session attributes copied to it (if 
     * <tt>migrateSessionAttributes</tt> is set) and the sessionRegistry updated with the new session information.
     */
    protected void startNewSessionIfRequired(HttpServletRequest request, HttpServletResponse response) {            
        SessionUtils.startNewSessionIfRequired(request, migrateSessionAttributes, sessionRegistry);
    }
}

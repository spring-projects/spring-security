package org.springframework.security.cas.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Default RequestMatcher implementation for the {@link TriggerCasGatewayFilter}.
 * 
 * This RequestMatcher returns <code>true</code> iff :
 * <ul>
 * <li>
 * User is not already authenticated (see {@link #isAuthenticated})</li>
 * <li>
 * The request was not previously gatewayed</li>
 * <li>
 * The request matches additional criteria (see {@link #performGatewayAuthentication})</li>
 * </ul>
 * 
 * Implementors can override this class to customize the authentication check and the gateway criteria.
 * <p>
 * The request is marked as "gatewayed" using the configured {@link GatewayResolver} to avoid infinite loop.
 * 
 * @author Michael Remond
 * 
 */
public class CasCookieGatewayRequestMatcher implements RequestMatcher {

    // ~ Instance fields
    // ================================================================================================

    private ServiceProperties serviceProperties;

	private String cookieName;
	
    private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();

    // ~ Constructors
    // ===================================================================================================

    public CasCookieGatewayRequestMatcher(ServiceProperties serviceProperties, final String cookieName) {
        Assert.notNull(serviceProperties, "serviceProperties cannot be null");
        this.serviceProperties = serviceProperties;
        this.cookieName = cookieName;
    }

    public final boolean matches(HttpServletRequest request) {

        // Test if we are already authenticated
        if (isAuthenticated(request)) {
            return false;
        }

        // Test if the request was already gatewayed to avoid infinite loop
        final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(request, serviceProperties.getService());

        if (wasGatewayed) {
            return false;
        }

        // If request matches gateway criteria, we mark the request as gatewayed and return true to trigger a CAS
        // gateway authentication
        if (performGatewayAuthentication(request)) {
            gatewayStorage.storeGatewayInformation(request, serviceProperties.getService());
            return true;
        } else {
            return false;
        }
    }

    /**
     * Test if the user is authenticated in Spring Security. Default implementation test if the user is CAS
     * authenticated.
     * 
     * @param request
     * @return true if the user is authenticated
     */
    protected boolean isAuthenticated(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication instanceof CasAuthenticationToken;
    }

    /**
     * Method that determines if the current request triggers a CAS gateway authentication.
     * This implementation returns <code>true</code> only if a {@link Cookie} with the configured
	 * name is present at the request
     * 
     * @param request
     * @return true if the request must trigger a CAS gateway authentication
     */
	protected boolean performGatewayAuthentication(HttpServletRequest request) {
		if (!StringUtils.hasText(this.cookieName)) {
			return true;
		}
    	
    	Cookie[] cookies = request.getCookies();
		if (cookies == null || cookies.length == 0) {
			return false;
		}
        
        for (Cookie cookie: cookies) {
            // Check the cookie name. If it matches the configured cookie name, return true
            if (this.cookieName.equalsIgnoreCase(cookie.getName())) {
                return true;
            }
        }
        return false;
    }

    public void setGatewayStorage(GatewayResolver gatewayStorage) {
        Assert.notNull(gatewayStorage, "gatewayStorage cannot be null");
        this.gatewayStorage = gatewayStorage;
    }
    
	public String getCookieName() {
		return cookieName;
	}

	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}
}
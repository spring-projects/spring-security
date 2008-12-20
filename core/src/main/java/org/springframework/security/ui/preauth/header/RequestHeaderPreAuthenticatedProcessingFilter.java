package org.springframework.security.ui.preauth.header;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.ui.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.util.Assert;

/**
 * A simple pre-authenticated filter which obtains the username from a request header, for use with systems such as
 * CA Siteminder.
 * <p>
 * As with most pre-authenticated scenarios, it is essential that the external authentication system is set up
 * correctly as this filter does no authentication whatsoever. All the protection is assumed to be provided externally 
 * and if this filter is included inappropriately in a configuration, it would be possible  to assume the 
 * identity of a user merely by setting the correct header name. This also means it should not be used in combination
 * with other Spring Security authentication mechanisms such as form login, as this would imply there was a means of
 * bypassing the external system which would be risky.
 * <p>
 * The property <tt>principalRequestHeader</tt> is the name of the request header that contains the username. It 
 * defaults to "SM_USER" for compatibility with Siteminder.
 * 
 * 
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class RequestHeaderPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {
    private String principalRequestHeader = "SM_USER"; 
    private String credentialsRequestHeader;

    /**
     * Read and returns the header named by <tt>principalRequestHeader</tt> from the request.
     * 
     * @throws PreAuthenticatedCredentialsNotFoundException if the header is missing 
     */
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String principal = request.getHeader(principalRequestHeader);
        
        if (principal == null) {
            throw new PreAuthenticatedCredentialsNotFoundException(principalRequestHeader 
                    + " header not found in request.");
        }

        return principal;
    }    
    
    /**
     * Credentials aren't usually applicable, but if a <tt>credentialsRequestHeader</tt> is set, this
     * will be read and used as the credentials value. Otherwise a dummy value will be used. 
     */
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        if (credentialsRequestHeader != null) {
            String credentials = request.getHeader(credentialsRequestHeader);
            
            return credentials;
        }

        return "N/A";
    }
    
    public void setPrincipalRequestHeader(String principalRequestHeader) {
        Assert.hasText(principalRequestHeader, "principalRequestHeader must not be empty or null");
        this.principalRequestHeader = principalRequestHeader;
    }

    public void setCredentialsRequestHeader(String credentialsRequestHeader) {
        Assert.hasText(credentialsRequestHeader, "credentialsRequestHeader must not be empty or null");        
        this.credentialsRequestHeader = credentialsRequestHeader;
    }

    public int getOrder() {
        return FilterChainOrder.PRE_AUTH_FILTER;
    }
}

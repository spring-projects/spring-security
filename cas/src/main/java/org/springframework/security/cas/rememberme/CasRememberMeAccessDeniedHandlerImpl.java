package org.springframework.security.cas.rememberme;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * This class is in charge of handling access denied taking into account CAS remember me feature.<br />
 * If the user has already a CAS remember me authentication token and is access denied, send him to CAS server with renew=true parameter to
 * force CAS server to "forget" previous identity and user to authenticate again.
 * 
 * @author Jerome Leleu
 */
public class CasRememberMeAccessDeniedHandlerImpl extends AccessDeniedHandlerImpl {
    
    private CasAuthenticationEntryPoint casAuthenticationEntryPoint = null;
    
    private RequestCache requestCache = null;
    
    private CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator = new CasAuthenticationTokenEvaluator();
    
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // if it's a CAS remember me authentication, do a specific CAS round-trip
        if (casAuthenticationTokenEvaluator.isRememberMe(authentication)) {
            // like sendStartAuthentication method in ExceptionTranslationFilter class
            SecurityContextHolder.getContext().setAuthentication(null);
            requestCache.saveRequest(request, response);
            logger.debug("Calling Authentication entry point.");
            casAuthenticationEntryPoint
                .commence(request,
                          response,
                          new InsufficientAuthenticationException(
                                                                  "Full CAS authentication is required to access this resource"));
        } else {
            super.handle(request, response, accessDeniedException);
        }
    }
    
    public CasAuthenticationEntryPoint getCasAuthenticationEntryPoint() {
        return casAuthenticationEntryPoint;
    }
    
    public void setCasAuthenticationEntryPoint(CasAuthenticationEntryPoint casAuthenticationEntryPoint) {
        this.casAuthenticationEntryPoint = casAuthenticationEntryPoint;
    }
    
    public RequestCache getRequestCache() {
        return requestCache;
    }
    
    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
    
    public CasAuthenticationTokenEvaluator getCasAuthenticationTokenEvaluator() {
        return casAuthenticationTokenEvaluator;
    }
    
    public void setCasAuthenticationTokenEvaluator(CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator) {
        this.casAuthenticationTokenEvaluator = casAuthenticationTokenEvaluator;
    }
    
    public void setErrorPage(String errorPage) {
        super.setErrorPage(errorPage);
    }
}

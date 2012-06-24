package org.springframework.security.cas.rememberme;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

/**
 * This class is in charge of handling access denied taking into account CAS remember me feature.
 * <p>
 * If the user has already a CAS remember me authentication token and is access denied, send him to CAS server with renew=true parameter to
 * force CAS server to "forget" previous identity and user to authenticate again.
 * <p>
 * The CasAuthenticationEntryPoint bean has to be specified for this class, it's the default CAS entry point used in the configuration.
 * 
 * @author Jerome Leleu
 * @since 3.1.1
 */
public class CasRememberMeAccessDeniedHandlerImpl extends AccessDeniedHandlerImpl implements InitializingBean {
    
    private RequestCache requestCache = new HttpSessionRequestCache();
    
    private CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator = new CasAuthenticationTokenEvaluator();
    
    private CasAuthenticationEntryPoint casAuthenticationEntryPoint = null;
    
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // if it's a CAS remember me authentication, do a specific CAS server round-trip
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
    
    /**
     * This setter is not a real one as it doesn't set directly a private property, instead it clones the entry point to a new one, setting
     * the renew parameter to true to allow to login into CAS server even if the user is already authenticated.
     * 
     * @param casAuthenticationEntryPoint
     */
    public void setCasAuthenticationEntryPoint(CasAuthenticationEntryPoint casAuthenticationEntryPoint) {
        this.casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        this.casAuthenticationEntryPoint.setLoginUrl(casAuthenticationEntryPoint.getLoginUrl());
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(casAuthenticationEntryPoint.getServiceProperties().getService());
        // use renew parameter when redirecting to CAS server as it will be used to "override" a previous CAS remember me authentication
        serviceProperties.setSendRenew(true);
        this.casAuthenticationEntryPoint.setServiceProperties(serviceProperties);
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
    
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.casAuthenticationEntryPoint, "casAuthenticationEntryPoint must be specified");
    }
}

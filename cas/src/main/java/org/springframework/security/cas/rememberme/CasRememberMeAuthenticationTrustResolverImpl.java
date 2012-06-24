package org.springframework.security.cas.rememberme;

import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * This class is an authentication trust resolver taking into account the CAS remember me feature.
 * 
 * @author Jerome Leleu
 * @since 3.1.1
 */
public class CasRememberMeAuthenticationTrustResolverImpl extends AuthenticationTrustResolverImpl {
    
    private CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator = new CasAuthenticationTokenEvaluator();
    
    public boolean isRememberMe(Authentication authentication) {
        // if it's a Spring Security remember me
        if (super.isRememberMe(authentication)) {
            return true;
        }
        
        // else if it's a CAS remember me
        return casAuthenticationTokenEvaluator.isRememberMe(authentication);
    }
    
    public CasAuthenticationTokenEvaluator getCasAuthenticationTokenEvaluator() {
        return casAuthenticationTokenEvaluator;
    }
    
    public void setCasAuthenticationTokenEvaluator(CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator) {
        this.casAuthenticationTokenEvaluator = casAuthenticationTokenEvaluator;
    }
}

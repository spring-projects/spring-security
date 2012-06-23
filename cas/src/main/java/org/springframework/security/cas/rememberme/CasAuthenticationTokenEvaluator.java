package org.springframework.security.cas.rememberme;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * This class evaluates if the CAS authentication token is in remember me mode.
 * 
 * @author Jerome Leleu
 */
public class CasAuthenticationTokenEvaluator {
    
    private static final String REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
    
    public boolean isRememberMe(Authentication authentication) {
        // if CAS token
        if (authentication instanceof CasAuthenticationToken) {
            CasAuthenticationToken casToken = (CasAuthenticationToken) authentication;
            Assertion assertion = casToken.getAssertion();
            // if "remember me"
            return ("true".equals(assertion.getPrincipal().getAttributes().get(REMEMBER_ME_ATTRIBUTE_NAME)));
        }
        
        return false;
    }
}

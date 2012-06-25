package org.springframework.security.web.access.expression;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultWebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {
    
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    
    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
                                                                        FilterInvocation fi) {
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(authentication, fi);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(authenticationTrustResolver);
        root.setRoleHierarchy(getRoleHierarchy());
        return root;
    }
    
    public AuthenticationTrustResolver getAuthenticationTrustResolver() {
        return authenticationTrustResolver;
    }
    
    public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver) {
        this.authenticationTrustResolver = authenticationTrustResolver;
    }
}

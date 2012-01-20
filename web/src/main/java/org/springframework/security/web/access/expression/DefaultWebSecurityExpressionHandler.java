package org.springframework.security.web.access.expression;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultWebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {
	
	private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(authentication, fi);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(trustResolver);
        root.setRoleHierarchy(getRoleHierarchy());
        return root;
    }
}

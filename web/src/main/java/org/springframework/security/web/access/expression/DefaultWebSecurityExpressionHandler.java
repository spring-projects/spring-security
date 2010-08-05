package org.springframework.security.web.access.expression;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.SecurityExpressionRootPropertyAccessor;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * Facade which isolates Spring Security's requirements for evaluating web-security expressions
 * from the implementation of the underlying expression objects.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultWebSecurityExpressionHandler implements WebSecurityExpressionHandler, ApplicationContextAware {

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final ExpressionParser expressionParser = new SpelExpressionParser();
    private final SecurityExpressionRootPropertyAccessor sxrpa = new SecurityExpressionRootPropertyAccessor();
    private RoleHierarchy roleHierarchy;
    private ApplicationContext applicationContext;

    public ExpressionParser getExpressionParser() {
        return expressionParser;
    }

    public EvaluationContext createEvaluationContext(Authentication authentication, FilterInvocation fi) {
        SecurityExpressionRoot root = new WebSecurityExpressionRoot(authentication, fi);
        root.setTrustResolver(trustResolver);
        root.setRoleHierarchy(roleHierarchy);
        root.setApplicationContext(applicationContext);
        StandardEvaluationContext ctx = new StandardEvaluationContext(root);
        ctx.addPropertyAccessor(sxrpa);

        return ctx;
    }

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}

package org.springframework.security.web.access.expression;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * Facade which isolates Spring Security's requirements for evaluating web-security expressions
 * from the implementation of the underlying expression objects.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultWebSecurityExpressionHandler implements WebSecurityExpressionHandler {

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private ExpressionParser expressionParser = new SpelExpressionParser();

    public ExpressionParser getExpressionParser() {
        return expressionParser;
    }

    public EvaluationContext createEvaluationContext(Authentication authentication, FilterInvocation fi) {
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        SecurityExpressionRoot root = new WebSecurityExpressionRoot(authentication, fi);
        root.setTrustResolver(trustResolver);
        ctx.setRootObject(root);

        return ctx;
    }
}

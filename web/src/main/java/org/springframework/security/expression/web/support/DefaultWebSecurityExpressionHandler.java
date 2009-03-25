package org.springframework.security.expression.web.support;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.antlr.SpelAntlrExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.expression.support.SecurityExpressionRoot;
import org.springframework.security.expression.web.WebSecurityExpressionHandler;
import org.springframework.security.intercept.web.FilterInvocation;

/**
 * Facade which isolates Spring Security's requirements for evaluating web-security expressions
 * from the implementation of the underlying expression objects.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class DefaultWebSecurityExpressionHandler implements WebSecurityExpressionHandler {

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private ExpressionParser expressionParser = new SpelAntlrExpressionParser();

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

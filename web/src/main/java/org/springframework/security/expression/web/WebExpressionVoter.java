package org.springframework.security.expression.web;

import java.util.List;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.expression.ExpressionUtils;
import org.springframework.security.expression.MethodSecurityExpressionHandler;
import org.springframework.security.expression.support.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.expression.web.support.DefaultWebSecurityExpressionHandler;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.vote.AccessDecisionVoter;

/**
 * Voter which handles web authorisation decisions.
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class WebExpressionVoter implements AccessDecisionVoter {
    private WebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();

    public int vote(Authentication authentication, Object object, List<ConfigAttribute> attributes) {
        assert authentication != null;
        assert object != null;
        assert attributes != null;

        WebExpressionConfigAttribute weca = findConfigAttribute(attributes);

        if (weca == null) {
            return ACCESS_ABSTAIN;
        }

        FilterInvocation fi = (FilterInvocation)object;
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, fi);

        return ExpressionUtils.evaluateAsBoolean(weca.getAuthorizeExpression(), ctx) ?
                ACCESS_GRANTED : ACCESS_DENIED;
    }

    private WebExpressionConfigAttribute findConfigAttribute(List<ConfigAttribute> attributes) {
        for (ConfigAttribute attribute : attributes) {
            if (attribute instanceof WebExpressionConfigAttribute) {
                return (WebExpressionConfigAttribute)attribute;
            }
        }
        return null;
    }

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof WebExpressionConfigAttribute;
    }

    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(FilterInvocation.class);
    }

    public void setExpressionHandler(WebSecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}

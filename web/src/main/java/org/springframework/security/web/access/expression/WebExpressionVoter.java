package org.springframework.security.web.access.expression;

import java.util.Collection;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * Voter which handles web authorisation decisions.
 * @author Luke Taylor
 * @since 3.0
 */
public class WebExpressionVoter implements AccessDecisionVoter {
    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
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

    private WebExpressionConfigAttribute findConfigAttribute(Collection<ConfigAttribute> attributes) {
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

    public void setExpressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}

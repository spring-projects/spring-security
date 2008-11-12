package org.springframework.security.expression.web;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.expression.SecurityExpressionHandler;
import org.springframework.security.expression.support.DefaultSecurityExpressionHandler;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.vote.AccessDecisionVoter;

/**
 * Voter which handles web authorisation decisions.
 * @author Luke Taylor
 * @version $Id$
 * @since
 */
public class WebExpressionVoter implements AccessDecisionVoter {
    private SecurityExpressionHandler expressionHandler = new DefaultSecurityExpressionHandler();

    public int vote(Authentication authentication, Object object, List<ConfigAttribute> attributes) {
        WebExpressionConfigAttribute weca = findConfigAttribute(attributes);

        if (weca == null) {
            return ACCESS_ABSTAIN;
        }

        FilterInvocation fi = (FilterInvocation)object;
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, fi);


        weca.getAuthorizeExpression();

        return 0;
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

    public boolean supports(Class<? extends Object> clazz) {
        return clazz.isAssignableFrom(FilterInvocation.class);
    }

    public void setExpressionHandler(SecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}

package org.springframework.security.access.expression.method;

import java.util.Collection;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.Authentication;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.support.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.vote.AccessDecisionVoter;

/**
 * Voter which performs the actions for @PreFilter and @PostAuthorize annotations.
 * <p>
 * If only a @PreFilter condition is specified, it will vote to grant access, otherwise it will vote
 * to grant or deny access depending on whether the @PostAuthorize expression evaluates to 'true' or 'false',
 * respectively.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class MethodExpressionVoter implements AccessDecisionVoter {
    protected final Log logger = LogFactory.getLog(getClass());

    private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof AbstractExpressionBasedMethodConfigAttribute;
    }

    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(MethodInvocation.class);
    }

    public int vote(Authentication authentication, Object object, List<ConfigAttribute> attributes) {
        PreInvocationExpressionAttribute mace = findMethodAccessControlExpression(attributes);

        if (mace == null) {
            // No expression based metadata, so abstain
            return ACCESS_ABSTAIN;
        }

        MethodInvocation mi = (MethodInvocation)object;
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        Expression preFilter = mace.getFilterExpression();
        Expression preAuthorize = mace.getAuthorizeExpression();

        if (preFilter != null) {
            Object filterTarget = findFilterTarget(mace.getFilterTarget(), ctx, mi);

            expressionHandler.filter(filterTarget, preFilter, ctx);
        }

        if (preAuthorize == null) {
            return ACCESS_GRANTED;
        }

        return ExpressionUtils.evaluateAsBoolean(preAuthorize, ctx) ? ACCESS_GRANTED : ACCESS_DENIED;
    }

    private Object findFilterTarget(String filterTargetName, EvaluationContext ctx, MethodInvocation mi) {
        Object filterTarget = null;

        if (filterTargetName.length() > 0) {
            filterTarget = ctx.lookupVariable(filterTargetName);
            if (filterTarget == null) {
                throw new IllegalArgumentException("Filter target was null, or no argument with name "
                        + filterTargetName + " found in method");
            }
        } else if (mi.getArguments().length == 1) {
            Object arg = mi.getArguments()[0];
            if (arg.getClass().isArray() ||
                arg instanceof Collection) {
                filterTarget = arg;
            }
            if (filterTarget == null) {
                throw new IllegalArgumentException("A PreFilter expression was set but the method argument type" +
                        arg.getClass() + " is not filterable");
            }
        }

        if (filterTarget.getClass().isArray()) {
            throw new IllegalArgumentException("Pre-filtering on array types is not supported. " +
                    "Using a Collection will solve this problem");
        }

        return filterTarget;
    }

    private PreInvocationExpressionAttribute findMethodAccessControlExpression(List<ConfigAttribute> config) {
        // Find the MethodAccessControlExpression attribute
        for (ConfigAttribute attribute : config) {
            if (attribute instanceof PreInvocationExpressionAttribute) {
                return (PreInvocationExpressionAttribute)attribute;
            }
        }

        return null;
    }

    public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}

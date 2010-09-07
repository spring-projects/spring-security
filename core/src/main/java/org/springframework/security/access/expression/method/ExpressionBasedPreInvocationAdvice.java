/**
 *
 */
package org.springframework.security.access.expression.method;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;

/**
 * Method pre-invocation handling based on expressions.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class ExpressionBasedPreInvocationAdvice implements PreInvocationAuthorizationAdvice {
    private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

    public boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute attr) {
        PreInvocationExpressionAttribute preAttr = (PreInvocationExpressionAttribute) attr;
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        Expression preFilter = preAttr.getFilterExpression();
        Expression preAuthorize = preAttr.getAuthorizeExpression();

        if (preFilter != null) {
            Object filterTarget = findFilterTarget(preAttr.getFilterTarget(), ctx, mi);

            expressionHandler.filter(filterTarget, preFilter, ctx);
        }

        if (preAuthorize == null) {
            return true;
        }

        return ExpressionUtils.evaluateAsBoolean(preAuthorize, ctx);
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
            if (arg.getClass().isArray() || arg instanceof Collection<?>) {
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


    public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}

package org.springframework.security.expression.support;

import java.lang.reflect.Method;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.StandardEvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.expression.ExpressionUtils;
import org.springframework.security.expression.SecurityExpressionRoot;
import org.springframework.security.vote.AccessDecisionVoter;
import org.springframework.util.ClassUtils;

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

    // TODO: Share this between classes
    private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof AbstractExpressionBasedMethodConfigAttribute;
    }

    public boolean supports(Class clazz) {
        return clazz.isAssignableFrom(MethodInvocation.class);
    }

    public int vote(Authentication authentication, Object object, List<ConfigAttribute> attributes) {
        PreInvocationExpressionConfigAttribute mace = findMethodAccessControlExpression(attributes);

        if (mace == null) {
            // No expression based metadata, so abstain
            return ACCESS_ABSTAIN;
        }

        StandardEvaluationContext ctx = new StandardEvaluationContext();
        Object filterTarget =
            populateContextVariablesAndFindFilterTarget(ctx, (MethodInvocation)object, mace.getFilterTarget());

        ctx.setRootObject(new SecurityExpressionRoot(authentication));

        Expression preFilter = mace.getFilterExpression();
        Expression preAuthorize = mace.getAuthorizeExpression();

        if (preFilter != null) {
            // TODO: Allow null target if only single parameter, or single collection/array?
            ExpressionUtils.doFilter(filterTarget, preFilter, ctx);
        }

        if (preAuthorize == null) {
            return ACCESS_GRANTED;
        }

        return ExpressionUtils.evaluateAsBoolean(preAuthorize, ctx) ? ACCESS_GRANTED : ACCESS_DENIED;
    }

    private Object populateContextVariablesAndFindFilterTarget(EvaluationContext ctx, MethodInvocation mi,
            String filterTargetName) {

        Object[] args = mi.getArguments();
        Object targetObject = mi.getThis();
        Method method = ClassUtils.getMostSpecificMethod(mi.getMethod(), targetObject.getClass());
        Object filterTarget = null;
        String[] paramNames = parameterNameDiscoverer.getParameterNames(method);

        for(int i=0; i < args.length; i++) {
            ctx.setVariable(paramNames[i], args[i]);
            if (filterTargetName != null && paramNames[i].equals(filterTargetName)) {
                filterTarget = args[i];
            }
        }

        if (filterTargetName != null) {
            if (filterTarget == null) {
                throw new IllegalArgumentException("No filter target argument with name " + filterTargetName +
                        " found in method: " + method.getName());
            }
            if (filterTarget.getClass().isArray()) {
                throw new IllegalArgumentException("Pre-filtering on array types is not supported. Changing '" +
                        filterTargetName +"' to a collection will solve this problem");
            }
        }

        return filterTarget;
    }

    private PreInvocationExpressionConfigAttribute findMethodAccessControlExpression(List<ConfigAttribute> config) {
        // Find the MethodAccessControlExpression attribute
        for (ConfigAttribute attribute : config) {
            if (attribute instanceof PreInvocationExpressionConfigAttribute) {
                return (PreInvocationExpressionConfigAttribute)attribute;
            }
        }

        return null;
    }
}

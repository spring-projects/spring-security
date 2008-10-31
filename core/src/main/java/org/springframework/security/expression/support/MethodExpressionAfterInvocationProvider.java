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
import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.afterinvocation.AfterInvocationProvider;
import org.springframework.security.expression.ExpressionUtils;
import org.springframework.security.expression.SecurityExpressionRoot;
import org.springframework.util.ClassUtils;

/**
 * AfterInvocationProvider which handles the @PostAuthorize and @PostFilter annotation expressions.
 *
 * @author Luke Taylor
 * @verson $Id$
 * @since 2.5
 */
public class MethodExpressionAfterInvocationProvider implements AfterInvocationProvider {

    protected final Log logger = LogFactory.getLog(getClass());

    private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();

    public Object decide(Authentication authentication, Object object, List<ConfigAttribute> config, Object returnedObject)
            throws AccessDeniedException {

        PostInvocationExpressionAttribute mca = findMethodAccessControlExpression(config);

        if (mca == null) {
            return returnedObject;
        }

        StandardEvaluationContext ctx = new StandardEvaluationContext();
        populateContextVariables(ctx, (MethodInvocation) object);
        SecurityExpressionRoot expressionRoot = new SecurityExpressionRoot(authentication);
        ctx.setRootObject(expressionRoot);

        Expression postFilter = mca.getFilterExpression();
        Expression postAuthorize = mca.getAuthorizeExpression();

        if (postFilter != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Applying PostFilter expression " + postFilter);
            }

            if (returnedObject != null) {
                returnedObject = ExpressionUtils.doFilter(returnedObject, postFilter, ctx);
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Return object is null, filtering will be skipped");
                }
            }
        }

        expressionRoot.setReturnObject(returnedObject);

        if (postAuthorize != null && !ExpressionUtils.evaluateAsBoolean(postAuthorize, ctx)) {
            if (logger.isDebugEnabled()) {
                logger.debug("PostAuthorize expression rejected access");
            }
            throw new AccessDeniedException("Access is denied");
        }

        return returnedObject;
    }

    private void populateContextVariables(EvaluationContext ctx, MethodInvocation mi) {
        Object[] args = mi.getArguments();
        Object targetObject = mi.getThis();
        Method method = ClassUtils.getMostSpecificMethod(mi.getMethod(), targetObject.getClass());
        String[] paramNames = parameterNameDiscoverer.getParameterNames(method);

        for(int i=0; i < args.length; i++) {
            ctx.setVariable(paramNames[i], args[i]);
        }
    }

    private PostInvocationExpressionAttribute findMethodAccessControlExpression(List<ConfigAttribute> config) {
        // Find the MethodAccessControlExpression attribute
        for (ConfigAttribute attribute : config) {
            if (attribute instanceof PostInvocationExpressionAttribute) {
                return (PostInvocationExpressionAttribute)attribute;
            }
        }

        return null;
    }

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof PostInvocationExpressionAttribute;
    }

    public boolean supports(Class clazz) {
        return clazz.isAssignableFrom(MethodInvocation.class);
    }



}

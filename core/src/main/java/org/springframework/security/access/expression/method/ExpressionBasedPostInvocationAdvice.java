package org.springframework.security.access.expression.method;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PostInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class ExpressionBasedPostInvocationAdvice implements PostInvocationAuthorizationAdvice{
    protected final Log logger = LogFactory.getLog(getClass());

    private final MethodSecurityExpressionHandler expressionHandler;

    public ExpressionBasedPostInvocationAdvice(MethodSecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }

    public Object after(Authentication authentication, MethodInvocation mi,
            PostInvocationAttribute postAttr, Object returnedObject) throws AccessDeniedException{
        PostInvocationExpressionAttribute pia = (PostInvocationExpressionAttribute) postAttr;
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        Expression postFilter = pia.getFilterExpression();
        Expression postAuthorize = pia.getAuthorizeExpression();

        if (postFilter != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Applying PostFilter expression " + postFilter);
            }

            if (returnedObject != null) {
                returnedObject = expressionHandler.filter(returnedObject, postFilter, ctx);
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Return object is null, filtering will be skipped");
                }
            }
        }

        expressionHandler.setReturnObject(returnedObject, ctx);

        if (postAuthorize != null && !ExpressionUtils.evaluateAsBoolean(postAuthorize, ctx)) {
            if (logger.isDebugEnabled()) {
                logger.debug("PostAuthorize expression rejected access");
            }
            throw new AccessDeniedException("Access is denied");
        }

        return returnedObject;
    }
}

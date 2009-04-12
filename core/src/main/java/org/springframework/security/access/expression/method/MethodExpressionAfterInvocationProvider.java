package org.springframework.security.access.expression.method;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.Authentication;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.support.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.AfterInvocationProvider;

/**
 * AfterInvocationProvider which handles the @PostAuthorize and @PostFilter annotation expressions.
 *
 * @author Luke Taylor
 * @verson $Id$
 * @since 2.5
 */
public class MethodExpressionAfterInvocationProvider implements AfterInvocationProvider {

    protected final Log logger = LogFactory.getLog(getClass());

    private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

    public Object decide(Authentication authentication, Object object, List<ConfigAttribute> config, Object returnedObject)
            throws AccessDeniedException {

        PostInvocationExpressionAttribute mca = findMethodAccessControlExpression(config);

        if (mca == null) {
            return returnedObject;
        }

        EvaluationContext ctx =
            expressionHandler.createEvaluationContext(authentication, (MethodInvocation)object);
        //SecurityExpressionRoot expressionRoot = new SecurityExpressionRoot(authentication);
        //ctx.setRootObject(expressionRoot);

        Expression postFilter = mca.getFilterExpression();
        Expression postAuthorize = mca.getAuthorizeExpression();

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

    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(MethodInvocation.class);
    }

    public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}

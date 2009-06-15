package org.springframework.security.access.expression.method;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * The standard implementation of <tt>SecurityExpressionHandler</tt>.
 * <p>
 * A single instance should usually be shared amongst the beans that require expression support.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultMethodSecurityExpressionHandler implements MethodSecurityExpressionHandler {

    protected final Log logger = LogFactory.getLog(getClass());

    private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();
    private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private ExpressionParser expressionParser = new SpelExpressionParser();

    public DefaultMethodSecurityExpressionHandler() {
    }

    /**
     * Uses a {@link MethodSecurityEvaluationContext} as the <tt>EvaluationContext</tt> implementation and
     * configures it with a {@link MethodSecurityExpressionRoot} instance as the expression root object.
     */
    public EvaluationContext createEvaluationContext(Authentication auth, MethodInvocation mi) {
        MethodSecurityEvaluationContext ctx = new MethodSecurityEvaluationContext(auth, mi, parameterNameDiscoverer);
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);
        root.setTrustResolver(trustResolver);
        root.setPermissionEvaluator(permissionEvaluator);
        ctx.setRootObject(root);

        return ctx;
    }

    @SuppressWarnings("unchecked")
    public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx) {
        MethodSecurityExpressionRoot rootObject = (MethodSecurityExpressionRoot) ctx.getRootObject().getValue();
        List retainList;

        if (logger.isDebugEnabled()) {
            logger.debug("Filtering with expression: " + filterExpression.getExpressionString());
        }

        if (filterTarget instanceof Collection) {
            Collection collection = (Collection)filterTarget;
            retainList = new ArrayList(collection.size());

            if (logger.isDebugEnabled()) {
                logger.debug("Filtering collection with " + collection.size() + " elements");
            }
            for (Object filterObject : (Collection)filterTarget) {
                rootObject.setFilterObject(filterObject);

                if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
                    retainList.add(filterObject);
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Retaining elements: " + retainList);
            }

            collection.clear();
            collection.addAll(retainList);

            return filterTarget;
        }

        if (filterTarget.getClass().isArray()) {
            Object[] array = (Object[])filterTarget;
            retainList = new ArrayList(array.length);

            if (logger.isDebugEnabled()) {
                logger.debug("Filtering collection with " + array.length + " elements");
            }

            for (int i = 0; i < array.length; i++) {
                rootObject.setFilterObject(array[i]);

                if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
                    retainList.add(array[i]);
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Retaining elements: " + retainList);
            }

            Object[] filtered = (Object[]) Array.newInstance(filterTarget.getClass().getComponentType(),
                            retainList.size());
            for (int i = 0; i < retainList.size(); i++) {
                filtered[i] = retainList.get(i);
            }

            return filtered;
        }

        throw new IllegalArgumentException("Filter target must be a collection or array type, but was " + filterTarget);
    }

    public ExpressionParser getExpressionParser() {
        return expressionParser;
    }

    public void setParameterNameDiscoverer(ParameterNameDiscoverer parameterNameDiscoverer) {
        this.parameterNameDiscoverer = parameterNameDiscoverer;
    }

    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public void setReturnObject(Object returnObject, EvaluationContext ctx) {
        ((MethodSecurityExpressionRoot)ctx.getRootObject().getValue()).setReturnObject(returnObject);
    }

}

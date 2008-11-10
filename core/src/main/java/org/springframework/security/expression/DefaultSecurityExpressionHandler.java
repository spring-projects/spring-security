package org.springframework.security.expression;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;

/**
 * The standard implementation of <tt>SecurityExpressionHandler</tt> which uses a {@link SecurityEvaluationContext}
 * as the <tt>EvaluationContext</tt> implementation and configures it with a {@link SecurityExpressionRoot} instance
 * as the expression root object.
 * <p>
 * A single instance should usually be shared between the expression voter and after-invocation provider.
 *
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class DefaultSecurityExpressionHandler implements SecurityExpressionHandler {

    protected final Log logger = LogFactory.getLog(getClass());

    private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();
    private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public DefaultSecurityExpressionHandler() {
    }

    public EvaluationContext createEvaluationContext(Authentication auth, MethodInvocation mi) {
        SecurityEvaluationContext ctx = new SecurityEvaluationContext(auth, mi, parameterNameDiscoverer);
        SecurityExpressionRoot root = new SecurityExpressionRoot(auth);
        root.setTrustResolver(trustResolver);
        root.setPermissionEvaluator(permissionEvaluator);
        ctx.setRootObject(root);

        return ctx;
    }

    public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx) {
        SecurityExpressionRoot rootObject = (SecurityExpressionRoot) ctx.getRootContextObject();
        Set removeList = new HashSet();

        if (logger.isDebugEnabled()) {
            logger.debug("Filtering with expression: " + filterExpression.getExpressionString());
        }

        if (filterTarget instanceof Collection) {
            Collection collection = (Collection)filterTarget;

            if (logger.isDebugEnabled()) {
                logger.debug("Filtering collection with " + collection.size() + " elements");
            }
            for (Object filterObject : (Collection)filterTarget) {
                rootObject.setFilterObject(filterObject);

                if (!ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
                    removeList.add(filterObject);
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Removing elements: " + removeList);
            }

            for(Object toRemove : removeList) {
                ((Collection)filterTarget).remove(toRemove);
            }

            return filterTarget;
        }

        if (filterTarget.getClass().isArray()) {
            Object[] array = (Object[])filterTarget;

            if (logger.isDebugEnabled()) {
                logger.debug("Filtering collection with " + array.length + " elements");
            }

            for (int i = 0; i < array.length; i++) {
                rootObject.setFilterObject(array[i]);

                if (!ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
                    removeList.add(array[i]);
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Removing elements: " + removeList);
            }

            Object[] filtered = (Object[]) Array.newInstance(filterTarget.getClass().getComponentType(),
                    array.length - removeList.size());
            for (int i = 0, j = 0; i < array.length; i++) {
                if (!removeList.contains(array[i])) {
                    filtered[j++] = array[i];
                }
            }

            return filtered;
        }

        throw new IllegalArgumentException("Filter target must be a collection or array type, but was " + filterTarget);
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
        ((SecurityExpressionRoot)ctx.getRootContextObject()).setReturnObject(returnObject);
    }
}

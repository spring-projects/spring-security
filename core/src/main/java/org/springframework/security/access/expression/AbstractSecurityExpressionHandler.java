package org.springframework.security.access.expression;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * Base implementation of the facade which isolates Spring Security's requirements for evaluating security expressions
 * from the implementation of the underlying expression objects.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public abstract class AbstractSecurityExpressionHandler<T> implements SecurityExpressionHandler<T>, ApplicationContextAware {
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final ExpressionParser expressionParser = new SpelExpressionParser();
    private ApplicationContextPropertyAccessor sxrpa = new ApplicationContextPropertyAccessor(null);
    private RoleHierarchy roleHierarchy;

    public final ExpressionParser getExpressionParser() {
        return expressionParser;
    }

    /**
     * Invokes the internal template methods to create {@code StandardEvaluationContext} and {@code SecurityExpressionRoot}
     * objects. The root object will be injected with references to the application context, the {@code roleHierarchy}
     * if set, and an {@code AuthenticationTrustResolver}.
     *
     * @param authentication the current authentication object
     * @param invocation the invocation (filter, method, channel)
     * @return the context object for use in evaluating the expression, populated with a suitable root object.
     */
    public final EvaluationContext createEvaluationContext(Authentication authentication, T invocation) {
        SecurityExpressionRoot root = createSecurityExpressionRoot(authentication, invocation);
        root.setTrustResolver(trustResolver);
        root.setRoleHierarchy(roleHierarchy);
        StandardEvaluationContext ctx = createEvaluationContextInternal(authentication, invocation);
        ctx.addPropertyAccessor(sxrpa);
        ctx.setRootObject(root);

        return ctx;
    }

    /**
     * Override to create a custom instance of {@code StandardEvaluationContext}.
     * <p>
     * The returned object will have a {@code SecurityExpressionRootPropertyAccessor} added, allowing beans in
     * the {@code ApplicationContext} to be accessed via expression properties.
     *
     * @param authentication the current authentication object
     * @param invocation the invocation (filter, method, channel)
     * @return A {@code StandardEvaluationContext} or potentially a custom subclass if overridden.
     */
    protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication, T invocation) {
        return new StandardEvaluationContext();
    }

    /**
     * Implement in order to create a root object of the correct type for the supported invocation type.
     *
     * @param authentication the current authentication object
     * @param invocation the invocation (filter, method, channel)
     * @return the object wh
     */
    protected abstract SecurityExpressionRoot createSecurityExpressionRoot(Authentication authentication, T invocation);

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    public void setApplicationContext(ApplicationContext applicationContext) {
        sxrpa = new ApplicationContextPropertyAccessor(applicationContext);
    }
}

package org.springframework.security.expression;

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.spel.standard.StandardEvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.util.ClassUtils;

/**
 * Internal security-specific EvaluationContext implementation which lazily adds the
 * method parameter values as variables (with the corresponding parameter names) if
 * and when they are required.
 *
 * @author Luke Taylor
 * @since 2.5
 */
public class SecurityEvaluationContext extends StandardEvaluationContext {
    private ParameterNameDiscoverer parameterNameDiscoverer;
    private boolean argumentsAdded;
    private MethodInvocation mi;

    /**
     * Intended for testing. Don't use in practice as it creates a new parameter resolver
     * for each instance. Use the constructor which takes the resolver, as an argument thus
     * allowing for caching.
     */
    public SecurityEvaluationContext(Authentication user, MethodInvocation mi) {
        this(user, mi, new LocalVariableTableParameterNameDiscoverer());
    }

    public SecurityEvaluationContext(Authentication user, MethodInvocation mi,
                    ParameterNameDiscoverer parameterNameDiscoverer) {
        this.mi = mi;
        this.parameterNameDiscoverer = parameterNameDiscoverer;
    }

    @Override
    public Object lookupVariable(String name) {
        Object variable = super.lookupVariable(name);
        if (variable != null) {
            return variable;
        }

        if (!argumentsAdded) {
            addArgumentsAsVariables();
        }

        return super.lookupVariable(name);
    }

    public void setParameterNameDiscoverer(ParameterNameDiscoverer parameterNameDiscoverer) {
        this.parameterNameDiscoverer = parameterNameDiscoverer;
    }

    private void addArgumentsAsVariables() {
        Object[] args = mi.getArguments();
        Object targetObject = mi.getThis();
        Method method = ClassUtils.getMostSpecificMethod(mi.getMethod(), targetObject.getClass());
        String[] paramNames = parameterNameDiscoverer.getParameterNames(method);

        for(int i=0; i < args.length; i++) {
            super.setVariable(paramNames[i], args[i]);
        }
    }

}

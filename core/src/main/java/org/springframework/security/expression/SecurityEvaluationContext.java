package org.springframework.security.expression;

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.spel.standard.StandardEvaluationContext;
import org.springframework.security.Authentication;
import org.springframework.util.ClassUtils;

/**
 *
 * @author Luke Taylor
 * @since 2.5
 */
public class SecurityEvaluationContext extends StandardEvaluationContext {

    private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();
    private boolean argumentsAdded;
    private MethodInvocation mi;

    public SecurityEvaluationContext(Authentication user, MethodInvocation mi) {
        setRootObject(new SecurityExpressionRoot(user));
        this.mi = mi;
    }

    @Override
    public Object lookupVariable(String name) {
        if (!argumentsAdded) {
            addArgumentsAsVariables();
        }

        return super.lookupVariable(name);
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

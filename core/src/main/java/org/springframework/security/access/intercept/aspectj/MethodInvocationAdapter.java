package org.springframework.security.access.intercept.aspectj;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.CodeSignature;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * Decorates a JoinPoint to allow it to be used with method-security infrastructure
 * classes which support {@code MethodInvocation} instances.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public final class MethodInvocationAdapter implements MethodInvocation {
    private final ProceedingJoinPoint jp;
    private final Method method;
    private final Object target;

    MethodInvocationAdapter(JoinPoint jp) {
        this.jp = (ProceedingJoinPoint)jp;
        if (jp.getTarget() != null) {
            target = jp.getTarget();
        } else {
            // SEC-1295: target may be null if an ITD is in use
            target = jp.getSignature().getDeclaringType();
        }
        String targetMethodName = jp.getStaticPart().getSignature().getName();
        Class<?>[] types = ((CodeSignature) jp.getStaticPart().getSignature()).getParameterTypes();
        Class<?> declaringType = jp.getStaticPart().getSignature().getDeclaringType();

        method = findMethod(targetMethodName, declaringType, types);

        if(method == null) {
            throw new IllegalArgumentException("Could not obtain target method from JoinPoint: '"+ jp + "'");
        }
    }

    private Method findMethod(String name, Class<?> declaringType, Class<?>[] params) {
        Method method = null;

        try {
            method = declaringType.getMethod(name, params);
        } catch (NoSuchMethodException ignored) {
        }

        if (method == null) {
            try {
                method = declaringType.getDeclaredMethod(name, params);
            } catch (NoSuchMethodException ignored) {
            }
        }

        return method;
    }

    public Method getMethod() {
        return method;
    }

    public Object[] getArguments() {
        return jp.getArgs();
    }

    public AccessibleObject getStaticPart() {
        return method;
    }

    public Object getThis() {
        return target;
    }

    public Object proceed() throws Throwable {
        return jp.proceed();
    }
}

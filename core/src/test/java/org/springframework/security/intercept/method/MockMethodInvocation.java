package org.springframework.security.intercept.method;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;

public class MockMethodInvocation implements MethodInvocation {
    private Method method;
    private Object targetObject;

    public MockMethodInvocation(Object targetObject, Class clazz, String methodName, Class... parameterTypes)
            throws NoSuchMethodException {
        this.method = clazz.getMethod(methodName, parameterTypes);
        this.targetObject = targetObject;
    }

    public Object[] getArguments() {
        return null;
    }

    public Method getMethod() {
        return method;
    }

    public AccessibleObject getStaticPart() {
        return null;
    }

    public Object getThis() {
        return targetObject;
    }

    public Object proceed() throws Throwable {
        return null;
    }
}

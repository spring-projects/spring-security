package org.springframework.security.integration.python;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.aopalliance.intercept.MethodInvocation;
import org.python.core.Py;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;
import org.springframework.util.ClassUtils;

public class PythonInterpreterPreInvocationAdvice implements PreInvocationAuthorizationAdvice{
    private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();

    public boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute preAttr) {
        PythonInterpreterPreInvocationAttribute pythonAttr = (PythonInterpreterPreInvocationAttribute) preAttr;
        String script = pythonAttr.getScript();

        PythonInterpreter python = new PythonInterpreter();
        python.set("authentication", authentication);
        python.set("args", createArgumentMap(mi));
        python.set("method", mi.getMethod().getName());
        Resource scriptResource = new PathMatchingResourcePatternResolver().getResource(script);

        try {
            python.execfile(scriptResource.getInputStream());
        } catch (IOException e) {
            throw new IllegalArgumentException("Couldn't run python script, " + script, e);
        }

        PyObject allowed = python.get("allow");

        if (allowed == null) {
            throw new IllegalStateException("Python script did not set the permit flag");
        }

        return Py.tojava(allowed, Boolean.class);
    }

    private Map<String,Object> createArgumentMap(MethodInvocation mi) {
        Object[] args = mi.getArguments();
        Object targetObject = mi.getThis();
        Method method = ClassUtils.getMostSpecificMethod(mi.getMethod(), targetObject.getClass());
        String[] paramNames = parameterNameDiscoverer.getParameterNames(method);

        Map<String,Object> argMap = new HashMap<String,Object>();
        for(int i=0; i < args.length; i++) {
            argMap.put(paramNames[i], args[i]);
        }

        return argMap;
    }
}

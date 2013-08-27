/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.servlet.support.csrf;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * Integration with Spring Web MVC that automatically adds the {@link CsrfToken}
 * into forms with hidden inputs when using Spring tag libraries.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CsrfRequestDataValueProcessor {
    private Pattern DISABLE_CSRF_TOKEN_PATTERN = Pattern.compile("(?i)^(GET|HEAD|TRACE|OPTIONS)$");

    private String DISABLE_CSRF_TOKEN_ATTR = "DISABLE_CSRF_TOKEN_ATTR";

    public String processAction(HttpServletRequest request, String action) {
        return action;
    }

    public String processAction(HttpServletRequest request, String action, String method) {
        if(method != null && DISABLE_CSRF_TOKEN_PATTERN.matcher(method).matches()) {
            request.setAttribute(DISABLE_CSRF_TOKEN_ATTR, Boolean.TRUE);
        } else {
            request.removeAttribute(DISABLE_CSRF_TOKEN_ATTR);
        }
        return action;
    }

    public String processFormFieldValue(HttpServletRequest request,
            String name, String value, String type) {
        return value;
    }

    public Map<String, String> getExtraHiddenFields(HttpServletRequest request) {
        if(Boolean.TRUE.equals(request.getAttribute(DISABLE_CSRF_TOKEN_ATTR))) {
            request.removeAttribute(DISABLE_CSRF_TOKEN_ATTR);
            return Collections.emptyMap();
        }

        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class
                .getName());
        if (token == null) {
            return Collections.emptyMap();
        }
        Map<String, String> hiddenFields = new HashMap<String, String>(1);
        hiddenFields.put(token.getParameterName(), token.getToken());
        return hiddenFields;
    }

    public String processUrl(HttpServletRequest request, String url) {
        return url;
    }

    CsrfRequestDataValueProcessor() {}

    /**
     * Creates an instance of {@link CsrfRequestDataValueProcessor} that
     * implements {@link RequestDataValueProcessor}. This is necessary to ensure
     * compatibility between Spring 3 and Spring 4.
     *
     * @return an instance of {@link CsrfRequestDataValueProcessor} that
     * implements {@link RequestDataValueProcessor}
     */
    public static RequestDataValueProcessor create() {
        CsrfRequestDataValueProcessor target= new CsrfRequestDataValueProcessor();
        ClassLoader classLoader = CsrfRequestDataValueProcessor.class.getClassLoader();
        Class<?>[] interfaces = new Class[] { RequestDataValueProcessor.class};
        TypeConversionInterceptor interceptor = new TypeConversionInterceptor(target);
        return (RequestDataValueProcessor) Proxy.newProxyInstance(classLoader, interfaces, interceptor);
    }

    /**
     * An {@link InvocationHandler} that assumes the target has all the method
     * defined on it, but the target does not implement the interface. This is
     * necessary to deal with the fact that Spring 3 and Spring 4 have different
     * definitions for the {@link RequestDataValueProcessor} interface.
     *
     * @author Rob Winch
     */
    private static class TypeConversionInterceptor implements InvocationHandler {

        private final Object target;

        public TypeConversionInterceptor(Object target) {
            this.target = target;
        }

        /* (non-Javadoc)
         * @see java.lang.reflect.InvocationHandler#invoke(java.lang.Object, java.lang.reflect.Method, java.lang.Object[])
         */
        public Object invoke(Object proxy, Method method, Object[] args)
                throws Throwable {
            Method methodToInvoke = ReflectionUtils.findMethod(target.getClass(), method.getName(), method.getParameterTypes());
            return methodToInvoke.invoke(target, args);
        }

        @Override
        public String toString() {
            return "RequestDataValueProcessorInterceptor [target=" + target
                    + "]";
        }
    }
}

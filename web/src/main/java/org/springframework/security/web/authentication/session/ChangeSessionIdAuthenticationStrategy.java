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
package org.springframework.security.web.authentication.session;

import java.lang.reflect.Method;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.util.ReflectionUtils;

/**
 * Uses {@link HttpServletRequest#changeSessionId()} to protect against session
 * fixation attacks. This is the default implementation for Servlet 3.1+.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ChangeSessionIdAuthenticationStrategy extends AbstractSessionFixationProtectionStrategy {
    private final Method changeSessionIdMethod;

    public ChangeSessionIdAuthenticationStrategy() {
        Method changeSessionIdMethod = ReflectionUtils.findMethod(HttpServletRequest.class, "changeSessionId");
        if(changeSessionIdMethod == null) {
            throw new IllegalStateException("HttpServletRequest.changeSessionId is undefined. Are you using a Servlet 3.1+ environment?");
        }
        this.changeSessionIdMethod = changeSessionIdMethod;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.web.authentication.session.AbstractSessionFixationProtectionStrategy#applySessionFixation(javax.servlet.http.HttpServletRequest)
     */
    @Override
    HttpSession applySessionFixation(HttpServletRequest request) {
        ReflectionUtils.invokeMethod(changeSessionIdMethod, request);
        return request.getSession();
    }
}

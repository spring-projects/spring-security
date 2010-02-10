/*
 * Copyright 2010 the original author or authors.
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
package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An AuthenticationEntryPoint which selects a concrete EntryPoint based on a
 * RequestMatcher evaluation.
 * 
 * @author Mike Wiesner
 * @since 3.0.2
 * @version $Id:$
 */
public class DelegatingAuthenticationEntryPoint implements
        AuthenticationEntryPoint, InitializingBean {

    private LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints;
    private AuthenticationEntryPoint defaultEntryPoint;

    public DelegatingAuthenticationEntryPoint(
            LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints) {
        this.entryPoints = entryPoints;
    }

    /**
     * EntryPoint which is used when no RequestMatcher returned true
     */
    public void setDefaultEntryPoint(AuthenticationEntryPoint defaultEntryPoint) {
        this.defaultEntryPoint = defaultEntryPoint;
    }


    public void commence(HttpServletRequest request,
            HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        for (RequestMatcher requestMatcher : entryPoints.keySet()) {
            if (requestMatcher.matches(request))
            {
               entryPoints.get(requestMatcher).commence(request, response, authException);
               return;
            }   
        }
        
        // No EntryPoint matched, use defaultEntryPoint
        defaultEntryPoint.commence(request, response, authException);
    }

    public void afterPropertiesSet() throws Exception {
       Assert.notEmpty(entryPoints, "entryPoints must be specified");
       Assert.notNull(defaultEntryPoint, "defaultEntryPoint must be specified");  
    }
    
    
}

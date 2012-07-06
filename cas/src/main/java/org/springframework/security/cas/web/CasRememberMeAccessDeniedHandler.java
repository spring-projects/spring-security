/*
 * Copyright 2012 the original author or authors.
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
package org.springframework.security.cas.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

/**
 * This class represents the <code>AccessDeniedHandlerImpl</code> dedicated to CAS authentication with remember-me support.
 * 
 * @author Jerome Leleu
 * @since 3.2.0
 */
public class CasRememberMeAccessDeniedHandler extends AccessDeniedHandlerImpl implements InitializingBean {
    
    private RequestCache requestCache = new HttpSessionRequestCache();
    
    private CasAuthenticationEntryPoint casAuthenticationEntryPoint;
    
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
        throws IOException, ServletException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // if CAS authentication token
        if (authentication != null && authentication instanceof CasAuthenticationToken) {
            CasAuthenticationToken casAuthenticationToken = (CasAuthenticationToken) authentication;
            // in remember-me mode
            if (casAuthenticationToken.isRememberMe()) {
                requestCache.saveRequest(request, response);
                logger.debug("Calling Authentication entry point with renew=true.");
                casAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("Full CAS authentication is required to access this resource"), true);
                return;
            }
        }
        
        super.handle(request, response, accessDeniedException);
    }
    
    public RequestCache getRequestCache() {
        return requestCache;
    }
    
    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
    
    public CasAuthenticationEntryPoint getCasAuthenticationEntryPoint() {
        return casAuthenticationEntryPoint;
    }
    
    public void setCasAuthenticationEntryPoint(CasAuthenticationEntryPoint casAuthenticationEntryPoint) {
        this.casAuthenticationEntryPoint = casAuthenticationEntryPoint;
    }
    
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.casAuthenticationEntryPoint, "casAuthenticationEntryPoint must be specified");
    }
}

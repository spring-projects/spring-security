/*
 * Copyright 2013-2013 the original author or authors.
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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.cas.authentication.TriggerCasGatewayException;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Triggers a CAS gateway authentication attempt.
 * <p>
 * This filter must be placed after the <code>ExceptionTranslationFilter</code> in the filter chain in order to start
 * the authentication process. Throws a {@link TriggerCasGatewayException} when the current request matches against the
 * configured {@link RequestMatcher}.
 * <p>
 * The default implementation you can use is {@link DefaultCasGatewayRequestMatcher}.
 * 
 * @author Michael Remond
 */
public class TriggerCasGatewayFilter extends GenericFilterBean {

    // ~ Instance fields
    // ================================================================================================

    private RequestMatcher requestMatcher;

    // ~ Constructors
    // ===================================================================================================

    public TriggerCasGatewayFilter(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.requestMatcher = requestMatcher;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
            ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (requestMatcher.matches(request)) {
            throw new TriggerCasGatewayException("Try a CAS gateway authentication");
        } else {
            // Continue in the chain
            chain.doFilter(request, response);
        }

    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

}
/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.servletapi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.util.Assert;

/**
 * Creates a {@link SecurityContextHolderAwareRequestWrapper}
 *
 * @author Rob Winch
 * @see SecurityContextHolderAwareRequestWrapper
 */
final class HttpServlet25RequestFactory implements HttpServletRequestFactory {
    private final String rolePrefix;
    private final AuthenticationTrustResolver trustResolver;

    HttpServlet25RequestFactory(AuthenticationTrustResolver trustResolver, String rolePrefix) {
        this.trustResolver = trustResolver;
        this.rolePrefix = rolePrefix;
    }

    public HttpServletRequest create(HttpServletRequest request, HttpServletResponse response) {
        return new SecurityContextHolderAwareRequestWrapper(request, trustResolver, rolePrefix) ;
    }
}

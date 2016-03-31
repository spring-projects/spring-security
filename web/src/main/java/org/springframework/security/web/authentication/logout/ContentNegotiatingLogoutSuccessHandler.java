/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.logout;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles the navigation on logout by deciding whether the logout request
 * came from Browser or AJAX/REST Client
 *
 * @author Shazin Sadakath
 */
public class ContentNegotiatingLogoutSuccessHandler implements LogoutSuccessHandler {

    private SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
    private HttpStatusReturningLogoutSuccessHandler httpStatusReturningLogoutSuccessHandler = new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT);

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Object xRequestedWith = request.getHeader("HTTP_X_REQUESTED_WITH");
        if(xRequestedWith != null && xRequestedWith.toString().equalsIgnoreCase("xmlhttprequest")) {
            httpStatusReturningLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        } else {
            simpleUrlLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        }
    }

    public SimpleUrlLogoutSuccessHandler getSimpleUrlLogoutSuccessHandler() {
        return simpleUrlLogoutSuccessHandler;
    }

    public void setSimpleUrlLogoutSuccessHandler(SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler) {
        Assert.notNull(simpleUrlLogoutSuccessHandler, "simpleUrlLogoutSuccessHandler must not be null");
        this.simpleUrlLogoutSuccessHandler = simpleUrlLogoutSuccessHandler;
    }

    public HttpStatusReturningLogoutSuccessHandler getHttpStatusReturningLogoutSuccessHandler() {
        return httpStatusReturningLogoutSuccessHandler;
    }

    public void setHttpStatusReturningLogoutSuccessHandler(HttpStatusReturningLogoutSuccessHandler httpStatusReturningLogoutSuccessHandler) {
        Assert.notNull(httpStatusReturningLogoutSuccessHandler, "httpStatusReturningLogoutSuccessHandler must not be null");
        this.httpStatusReturningLogoutSuccessHandler = httpStatusReturningLogoutSuccessHandler;
    }
}

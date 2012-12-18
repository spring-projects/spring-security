/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication;

import java.net.URL;

import org.springframework.security.core.AuthenticationException;

/**
 * Indicates the need to perform a redirect in the course of authentication, for example with a social OAuth
 * service provider.
 * 
 * @author Stefan Fussenegger
 * @author Yuan Ji 
 *
 */
@SuppressWarnings("serial")
public class AuthenticationRedirectException extends AuthenticationException{
    private final String redirectUrl;

    public AuthenticationRedirectException(URL redirectUrl) {
        this(redirectUrl.toString());
    }

    public AuthenticationRedirectException(String redirectUrl) {
        super("");
        this.redirectUrl = redirectUrl;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

}

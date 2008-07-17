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
package org.springframework.security.ui.preauth;

import javax.servlet.http.HttpServletRequest;

/**
 * Source of the username supplied with pre-authenticated authentication request. The username can
 * be supplied in the request: in cookie, request header, request parameter or as
 * ServletRequest.getRemoteUser().
 * 
 * @author Valery Tydykov
 * 
 */
public interface UsernameSource {
    /**
     * Obtain username supplied in the request.
     * 
     * @param request with username
     * @return username or null if not supplied
     */
    public String obtainUsername(HttpServletRequest request);
}

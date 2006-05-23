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

package org.acegisecurity.ui.logout;

import org.acegisecurity.Authentication;

import org.acegisecurity.context.SecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Performs a logout by modifying the {@link org.acegisecurity.context.SecurityContextHolder}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityContextLogoutHandler implements LogoutHandler {
    //~ Methods ========================================================================================================

    /**
     * Does not use any arguments. They can all be <code>null</code>.
     *
     * @param request not used (can be <code>null</code>)
     * @param response not used (can be <code>null</code>)
     * @param authentication not used (can be <code>null</code>)
     */
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        SecurityContextHolder.clearContext();
    }
}

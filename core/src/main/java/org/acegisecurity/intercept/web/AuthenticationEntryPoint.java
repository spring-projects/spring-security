/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Used by {@link SecurityEnforcementFilter} to commence an authentication
 * scheme.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AuthenticationEntryPoint {
    //~ Methods ================================================================

    /**
     * Commences an authentication scheme.
     * 
     * <P>
     * <code>SecurityEnforcementFilter</code> will populate the
     * <code>HttpSession</code> attribute named
     * <code>AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY</code>
     * with the requested target URL before calling this method.
     * </p>
     * 
     * <P>
     * Implementations should modify the headers on the
     * <code>ServletResponse</code> to as necessary to commence the
     * authentication process.
     * </p>
     *
     * @param request that resulted in an <code>AuthenticationException</code>
     * @param response so that the user agent can begin authentication
     */
    public void commence(ServletRequest request, ServletResponse response)
        throws IOException, ServletException;
}

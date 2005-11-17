/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.ui.rememberme;

import org.acegisecurity.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Implement by a class that is capable of providing a remember-me service.
 * 
 * <P>
 * Acegi Security filters (namely {@link
 * org.acegisecurity.ui.AbstractProcessingFilter} and {@link
 * org.acegisecurity.ui.rememberme.RememberMeProcessingFilter} will call
 * the methods provided by an implementation of this interface.
 * </p>
 * 
 * <P>
 * Implementations may implement any type of remember-me capability they wish.
 * Rolling cookies (as per <a
 * href="http://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice">http://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice</a>)
 * can be used, as can simple implementations that don't require a persistent
 * store. Implementations also determine the validity period of a remember-me
 * cookie.  This interface has been designed to accommodate any of these
 * remember-me models.
 * </p>
 * 
 * <p>
 * This interface does not define how remember-me services should offer a
 * "cancel all remember-me tokens" type capability, as this will be
 * implementation specific and requires no hooks into Acegi Security.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface RememberMeServices {
    //~ Methods ================================================================

    /**
     * This method will be called whenever the <code>SecurityContextHolder</code> does
     * not contain an <code>Authentication</code> and the Acegi Security
     * system wishes to provide an implementation with an opportunity to
     * authenticate the request using remember-me capabilities. Acegi Security
     * makes no attempt whatsoever to determine whether the browser has
     * requested remember-me services or presented a valid cookie. Such
     * determinations are left to the implementation. If a browser has
     * presented an unauthorised cookie for whatever reason, it should be
     * silently ignored and invalidated using the
     * <code>HttpServletResponse</code> object.
     * 
     * <p>
     * The returned <code>Authentication</code> must be acceptable to  {@link
     * org.acegisecurity.AuthenticationManager} or {@link
     * org.acegisecurity.providers.AuthenticationProvider} defined by the
     * web application. It is recommended {@link
     * org.acegisecurity.providers.rememberme.RememberMeAuthenticationToken}
     * be used in most cases, as it has a corresponding authentication
     * provider.
     * </p>
     *
     * @param request to look for a remember-me token within
     * @param response to change, cancel or modify the remember-me token
     *
     * @return a valid authentication object, or <code>null</code> if the
     *         request should not be authenticated
     */
    public Authentication autoLogin(HttpServletRequest request,
        HttpServletResponse response);

    /**
     * Called whenever an interactive authentication attempt was made, but the
     * credentials supplied by the user were missing or otherwise invalid.
     * Implementations should invalidate any and all remember-me tokens
     * indicated in the <code>HttpServletRequest</code>.
     *
     * @param request that contained an invalid authentication request
     * @param response to change, cancel or modify the remember-me token
     */
    public void loginFail(HttpServletRequest request,
        HttpServletResponse response);

    /**
     * Called whenever an interactive authentication attempt is successful. An
     * implementation may automatically set a remember-me token in the
     * <code>HttpServletResponse</code>, although this is not recommended.
     * Instead, implementations should typically look for a request parameter
     * that indicates the browser has presented an explicit request for
     * authentication to be remembered, such as the presence of a HTTP POST
     * parameter.
     *
     * @param request that contained the valid authentication request
     * @param response to change, cancel or modify the remember-me token
     * @param successfulAuthentication representing the successfully
     *        authenticated principal
     */
    public void loginSuccess(HttpServletRequest request,
        HttpServletResponse response, Authentication successfulAuthentication);
}

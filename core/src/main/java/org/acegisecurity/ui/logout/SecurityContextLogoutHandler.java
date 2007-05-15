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
import org.springframework.core.Ordered;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Performs a logout by modifying the
 * {@link org.acegisecurity.context.SecurityContextHolder}.
 * 
 * <p>
 * Will also invalidate the {@link HttpSession} if
 * {@link #isInvalidateHttpSession()} is <code>true</code> and the session is
 * not <code>null</code>.
 * 
 * @author Ben Alex
 * @version $Id: SecurityContextLogoutHandler.java 1784 2007-02-24 21:00:24Z
 * luke_t $
 */
public class SecurityContextLogoutHandler implements LogoutHandler, Ordered {
	// ~ Methods
	// ========================================================================================================

	private boolean invalidateHttpSession = true;

	private int order = Integer.MAX_VALUE; //~ default

	/**
	 * Requires the request to be passed in.
	 * 
	 * @param request from which to obtain a HTTP session (cannot be null)
	 * @param response not used (can be <code>null</code>)
	 * @param authentication not used (can be <code>null</code>)
	 */
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		Assert.notNull(request, "HttpServletRequest required");
		if (invalidateHttpSession) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				session.invalidate();
			}
		}

		SecurityContextHolder.clearContext();
	}

	public boolean isInvalidateHttpSession() {
		return invalidateHttpSession;
	}

	/**
	 * Causes the {@link HttpSession} to be invalidated when this
	 * {@link LogoutHandler} is invoked. Defaults to true.
	 * 
	 * @param invalidateHttpSession true if you wish the session to be
	 * invalidated (default) or false if it should not be
	 */
	public void setInvalidateHttpSession(boolean invalidateHttpSession) {
		this.invalidateHttpSession = invalidateHttpSession;
	}

	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

}

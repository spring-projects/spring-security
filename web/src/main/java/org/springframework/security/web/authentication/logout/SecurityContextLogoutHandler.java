/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * Performs a logout by modifying the
 * {@link org.springframework.security.core.context.SecurityContextHolder}.
 * <p>
 * Will also invalidate the {@link HttpSession} if {@link #isInvalidateHttpSession()} is
 * {@code true} and the session is not {@code null}.
 * <p>
 * Will also remove the {@link Authentication} from the current {@link SecurityContext} if
 * {@link #clearAuthentication} is set to true (default).
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class SecurityContextLogoutHandler implements LogoutHandler {
	protected final Log logger = LogFactory.getLog(this.getClass());

	private boolean invalidateHttpSession = true;
	private boolean clearAuthentication = true;

	// ~ Methods
	// ========================================================================================================

	/**
	 * Requires the request to be passed in.
	 *
	 * @param request from which to obtain a HTTP session (cannot be null)
	 * @param response not used (can be <code>null</code>)
	 * @param authentication not used (can be <code>null</code>)
	 */
	public void logout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		Assert.notNull(request, "HttpServletRequest required");
		if (invalidateHttpSession) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				logger.debug("Invalidating session: " + session.getId());
				session.invalidate();
			}
		}

		if (clearAuthentication) {
			SecurityContext context = SecurityContextHolder.getContext();
			context.setAuthentication(null);
		}

		SecurityContextHolder.clearContext();
	}

	public boolean isInvalidateHttpSession() {
		return invalidateHttpSession;
	}

	/**
	 * Causes the {@link HttpSession} to be invalidated when this {@link LogoutHandler} is
	 * invoked. Defaults to true.
	 *
	 * @param invalidateHttpSession true if you wish the session to be invalidated
	 * (default) or false if it should not be.
	 */
	public void setInvalidateHttpSession(boolean invalidateHttpSession) {
		this.invalidateHttpSession = invalidateHttpSession;
	}

	/**
	 * If true, removes the {@link Authentication} from the {@link SecurityContext} to
	 * prevent issues with concurrent requests.
	 *
	 * @param clearAuthentication true if you wish to clear the {@link Authentication}
	 * from the {@link SecurityContext} (default) or false if the {@link Authentication}
	 * should not be removed.
	 */
	public void setClearAuthentication(boolean clearAuthentication) {
		this.clearAuthentication = clearAuthentication;
	}
}

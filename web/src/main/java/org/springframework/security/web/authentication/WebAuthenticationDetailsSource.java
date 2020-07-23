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

package org.springframework.security.web.authentication;

import org.springframework.security.authentication.AuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

/**
 * Implementation of {@link AuthenticationDetailsSource} which builds the details object
 * from an <tt>HttpServletRequest</tt> object, creating a {@code WebAuthenticationDetails}
 * .
 *
 * @author Ben Alex
 */
public class WebAuthenticationDetailsSource
		implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

	/**
	 * @param context the {@code HttpServletRequest} object.
	 * @return the {@code WebAuthenticationDetails} containing information about the
	 * current request
	 */
	public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
		return new WebAuthenticationDetails(context);
	}

}

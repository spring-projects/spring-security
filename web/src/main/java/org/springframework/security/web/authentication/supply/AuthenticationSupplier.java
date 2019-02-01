/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.authentication.supply;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * Used in {@link GenericAuthenticationFilter} to provide requested
 * {@link Authentication} object, which is further used by
 * {@link AuthenticationManager} to authenticate user.
 *
 * @author Sergey Bespalov
 *
 * @see GenericAuthenticationFilter
 * @see AuthenticationSupplierRegistry
 */
public interface AuthenticationSupplier<T extends Authentication> extends AuthenticationEntryPoint {

	/**
	 * Supplies requested {@link Authentication}.
	 *
	 * @param request
	 * @return
	 * @throws AuthenticationException
	 */
	T supply(HttpServletRequest request) throws AuthenticationException;

	/**
	 * Provides supported {@link AuthenticationType}.
	 *
	 * @return
	 */
	AuthenticationType getAuthenticationType();

}

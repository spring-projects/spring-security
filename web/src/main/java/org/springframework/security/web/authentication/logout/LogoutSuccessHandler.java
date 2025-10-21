/*
 * Copyright 2004-present the original author or authors.
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

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;

/**
 * Strategy that is called after a successful logout by the {@link LogoutFilter}, to
 * handle redirection or forwarding to the appropriate destination.
 * <p>
 * Note that the interface is almost the same as {@link LogoutHandler} but may raise an
 * exception. <tt>LogoutHandler</tt> implementations expect to be invoked to perform
 * necessary cleanup, so should not throw exceptions.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface LogoutSuccessHandler {

	void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
			@Nullable Authentication authentication) throws IOException, ServletException;

}

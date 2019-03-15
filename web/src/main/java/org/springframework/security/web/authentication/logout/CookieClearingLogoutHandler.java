/*
 * Copyright 2002-2016 the original author or authors.
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

import java.util.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A logout handler which clears a defined list of cookies, using the context path as the
 * cookie path.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public final class CookieClearingLogoutHandler implements LogoutHandler {
	private final List<String> cookiesToClear;

	public CookieClearingLogoutHandler(String... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		this.cookiesToClear = Arrays.asList(cookiesToClear);
	}

	public void logout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		for (String cookieName : cookiesToClear) {
			Cookie cookie = new Cookie(cookieName, null);
			String cookiePath = request.getContextPath();
			if (!StringUtils.hasLength(cookiePath)) {
				cookiePath = "/";
			}
			cookie.setPath(cookiePath);
			cookie.setMaxAge(0);
			response.addCookie(cookie);
		}
	}
}

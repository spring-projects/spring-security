/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A logout handler which clears either - A defined list of cookie names, using the
 * context path as the cookie path OR - A given list of Cookies
 *
 * @author Luke Taylor
 * @author Onur Kagan Ozcan
 * @since 3.1
 */
public final class CookieClearingLogoutHandler implements LogoutHandler {

	private final List<Function<HttpServletRequest, Cookie>> cookiesToClear;

	public CookieClearingLogoutHandler(String... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		List<Function<HttpServletRequest, Cookie>> cookieList = new ArrayList<>();
		for (String cookieName : cookiesToClear) {
			Function<HttpServletRequest, Cookie> f = (request) -> {
				Cookie cookie = new Cookie(cookieName, null);
				String cookiePath = request.getContextPath() + "/";
				cookie.setPath(cookiePath);
				cookie.setMaxAge(0);
				cookie.setSecure(request.isSecure());
				return cookie;
			};
			cookieList.add(f);
		}
		this.cookiesToClear = cookieList;
	}

	/**
	 * @param cookiesToClear - One or more Cookie objects that must have maxAge of 0
	 * @since 5.2
	 */
	public CookieClearingLogoutHandler(Cookie... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		List<Function<HttpServletRequest, Cookie>> cookieList = new ArrayList<>();
		for (Cookie cookie : cookiesToClear) {
			Assert.isTrue(cookie.getMaxAge() == 0, "Cookie maxAge must be 0");
			Function<HttpServletRequest, Cookie> f = (request) -> cookie;
			cookieList.add(f);
		}
		this.cookiesToClear = cookieList;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		this.cookiesToClear.forEach(f -> response.addCookie(f.apply(request)));
	}

}

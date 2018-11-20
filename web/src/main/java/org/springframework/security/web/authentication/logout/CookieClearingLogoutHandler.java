/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.web.authentication.logout;

import java.util.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A logout handler which clears either
 * - A defined list of cookie names, using the context path as the cookie path
 * OR
 * - A given list of Cookies
 *
 * @author Luke Taylor
 * @since 3.1
 */
public final class CookieClearingLogoutHandler implements LogoutHandler {
	private final List<Object> cookiesToClear;

	public CookieClearingLogoutHandler(String... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		this.cookiesToClear =  Arrays.asList((Object[]) cookiesToClear);
	}

	/**
	 * @since 5.X
	 * @param cookiesToClear - One or more Cookie objects that must have maxAge of 0
	 */
	public CookieClearingLogoutHandler(Cookie... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		List<Object> cookieList = new ArrayList<Object>();
		for (Cookie cookie : cookiesToClear) {
			Assert.isTrue(cookie.getMaxAge() == 0, "Cookie maxAge must be 0");
			cookieList.add(cookie);
		}
		this.cookiesToClear = cookieList;
	}

	public void logout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		for (Object cookie : cookiesToClear) {
			Cookie realCookie = null;
			if (cookie instanceof String) {
				realCookie = new Cookie((String) cookie, null);
				String cookiePath = request.getContextPath() + "/";
				realCookie.setPath(cookiePath);
				realCookie.setMaxAge(0);
			}else if (cookie instanceof Cookie){
				realCookie = (Cookie) cookie;
			}
			response.addCookie(realCookie);
		}
	}
}

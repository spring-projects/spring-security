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

package org.springframework.security.web.savedrequest;

import java.io.Serializable;

import jakarta.servlet.http.Cookie;

import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * Stores off the values of a cookie in a serializable holder
 *
 * @author Ray Krueger
 */
public class SavedCookie implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String name;

	private final String value;

	private final String domain;

	private final int maxAge;

	private final String path;

	private final boolean secure;

	public SavedCookie(String name, String value, String domain, int maxAge, String path, boolean secure) {
		this.name = name;
		this.value = value;
		this.domain = domain;
		this.maxAge = maxAge;
		this.path = path;
		this.secure = secure;
	}

	public SavedCookie(Cookie cookie) {
		this(cookie.getName(), cookie.getValue(), cookie.getDomain(), cookie.getMaxAge(), cookie.getPath(),
				cookie.getSecure());
	}

	public String getName() {
		return this.name;
	}

	public String getValue() {
		return this.value;
	}

	public String getDomain() {
		return this.domain;
	}

	public int getMaxAge() {
		return this.maxAge;
	}

	public String getPath() {
		return this.path;
	}

	public boolean isSecure() {
		return this.secure;
	}

	public Cookie getCookie() {
		Cookie cookie = new Cookie(getName(), getValue());
		if (getDomain() != null) {
			cookie.setDomain(getDomain());
		}
		if (getPath() != null) {
			cookie.setPath(getPath());
		}
		cookie.setMaxAge(getMaxAge());
		cookie.setSecure(isSecure());
		return cookie;
	}

}

/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.firewall;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>
 * User's should consider using {@link StrictHttpFirewall} because rather than trying to
 * sanitize a malicious URL it rejects the malicious URL providing better security
 * guarantees.
 * <p>
 * Default implementation which wraps requests in order to provide consistent values of
 * the {@code servletPath} and {@code pathInfo}, which do not contain path parameters (as
 * defined in <a href="https://www.ietf.org/rfc/rfc2396.txt">RFC 2396</a>). Different
 * servlet containers interpret the servlet spec differently as to how path parameters are
 * treated and it is possible they might be added in order to bypass particular security
 * constraints. When using this implementation, they will be removed for all requests as
 * the request passes through the security filter chain. Note that this means that any
 * segments in the decoded path which contain a semi-colon, will have the part following
 * the semi-colon removed for request matching. Your application should not contain any
 * valid paths which contain semi-colons.
 * <p>
 * If any un-normalized paths are found (containing directory-traversal character
 * sequences), the request will be rejected immediately. Most containers normalize the
 * paths before performing the servlet-mapping, but again this is not guaranteed by the
 * servlet spec.
 *
 * @author Luke Taylor
 * @see StrictHttpFirewall
 */
public class DefaultHttpFirewall implements HttpFirewall {

	private boolean allowUrlEncodedSlash;

	@Override
	public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
		FirewalledRequest firewalledRequest = new RequestWrapper(request);
		if (!isNormalized(firewalledRequest.getServletPath()) || !isNormalized(firewalledRequest.getPathInfo())) {
			throw new RequestRejectedException(
					"Un-normalized paths are not supported: " + firewalledRequest.getServletPath()
							+ ((firewalledRequest.getPathInfo() != null) ? firewalledRequest.getPathInfo() : ""));
		}
		String requestURI = firewalledRequest.getRequestURI();
		if (containsInvalidUrlEncodedSlash(requestURI)) {
			throw new RequestRejectedException("The requestURI cannot contain encoded slash. Got " + requestURI);
		}
		return firewalledRequest;
	}

	@Override
	public HttpServletResponse getFirewalledResponse(HttpServletResponse response) {
		return new FirewalledResponse(response);
	}

	/**
	 * <p>
	 * Sets if the application should allow a URL encoded slash character.
	 * </p>
	 * <p>
	 * If true (default is false), a URL encoded slash will be allowed in the URL.
	 * Allowing encoded slashes can cause security vulnerabilities in some situations
	 * depending on how the container constructs the HttpServletRequest.
	 * </p>
	 * @param allowUrlEncodedSlash the new value (default false)
	 */
	public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
		this.allowUrlEncodedSlash = allowUrlEncodedSlash;
	}

	private boolean containsInvalidUrlEncodedSlash(String uri) {
		if (this.allowUrlEncodedSlash || uri == null) {
			return false;
		}
		return uri.contains("%2f") || uri.contains("%2F");
	}

	/**
	 * Checks whether a path is normalized (doesn't contain path traversal sequences like
	 * "./", "/../" or "/.")
	 * @param path the path to test
	 * @return true if the path doesn't contain any path-traversal character sequences.
	 */
	private boolean isNormalized(String path) {
		if (path == null) {
			return true;
		}
		for (int i = path.length(); i > 0;) {
			int slashIndex = path.lastIndexOf('/', i - 1);
			int gap = i - slashIndex;
			if (gap == 2 && path.charAt(slashIndex + 1) == '.') {
				// ".", "/./" or "/."
				return false;
			}
			if (gap == 3 && path.charAt(slashIndex + 1) == '.' && path.charAt(slashIndex + 2) == '.') {
				return false;
			}
			i = slashIndex;
		}
		return true;
	}

}

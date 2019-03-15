/*
 * Copyright 2012-2017 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A strict implementation of {@link HttpFirewall} that rejects any suspicious requests
 * with a {@link RequestRejectedException}.
 *
 * @author Rob Winch
 * @since 5.0.1
 */
public class StrictHttpFirewall implements HttpFirewall {
	private static final String ENCODED_PERCENT = "%25";

	private static final String PERCENT = "%";

	private static final List<String> FORBIDDEN_ENCODED_PERIOD = Collections.unmodifiableList(Arrays.asList("%2e", "%2E"));

	private static final List<String> FORBIDDEN_SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));

	private static final List<String> FORBIDDEN_FORWARDSLASH = Collections.unmodifiableList(Arrays.asList("%2f", "%2F"));

	private static final List<String> FORBIDDEN_BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));

	private Set<String> encodedUrlBlacklist = new HashSet<String>();

	private Set<String> decodedUrlBlacklist = new HashSet<String>();

	public StrictHttpFirewall() {
		urlBlacklistsAddAll(FORBIDDEN_SEMICOLON);
		urlBlacklistsAddAll(FORBIDDEN_FORWARDSLASH);
		urlBlacklistsAddAll(FORBIDDEN_BACKSLASH);

		this.encodedUrlBlacklist.add(ENCODED_PERCENT);
		this.encodedUrlBlacklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		this.decodedUrlBlacklist.add(PERCENT);
	}

	/**
	 *
	 * @param allowSemicolon
	 */
	public void setAllowSemicolon(boolean allowSemicolon) {
		if (allowSemicolon) {
			urlBlacklistsRemoveAll(FORBIDDEN_SEMICOLON);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_SEMICOLON);
		}
	}

	public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
		if (allowUrlEncodedSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_FORWARDSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_FORWARDSLASH);
		}
	}

	public void setAllowUrlEncodedPeriod(boolean allowUrlEncodedPeriod) {
		if (allowUrlEncodedPeriod) {
			this.encodedUrlBlacklist.removeAll(FORBIDDEN_ENCODED_PERIOD);
		} else {
			this.encodedUrlBlacklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		}
	}

	public void setAllowBackSlash(boolean allowBackSlash) {
		if (allowBackSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_BACKSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_BACKSLASH);
		}
	}

	public void setAllowUrlEncodedPercent(boolean allowUrlEncodedPercent) {
		if (allowUrlEncodedPercent) {
			this.encodedUrlBlacklist.remove(ENCODED_PERCENT);
			this.decodedUrlBlacklist.remove(PERCENT);
		} else {
			this.encodedUrlBlacklist.add(ENCODED_PERCENT);
			this.decodedUrlBlacklist.add(PERCENT);
		}
	}

	private void urlBlacklistsAddAll(Collection<String> values) {
		this.encodedUrlBlacklist.addAll(values);
		this.decodedUrlBlacklist.addAll(values);
	}

	private void urlBlacklistsRemoveAll(Collection<String> values) {
		this.encodedUrlBlacklist.removeAll(values);
		this.decodedUrlBlacklist.removeAll(values);
	}

	@Override
	public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
		rejectedBlacklistedUrls(request);

		if (!isNormalized(request)) {
			throw new RequestRejectedException("The request was rejected because the URL was not normalized.");
		}

		String requestUri = request.getRequestURI();
		if (!containsOnlyPrintableAsciiCharacters(requestUri)) {
			throw new RequestRejectedException("The requestURI was rejected because it can only contain printable ASCII characters.");
		}
		return new FirewalledRequest(request) {
			@Override
			public void reset() {
			}
		};
	}

	private void rejectedBlacklistedUrls(HttpServletRequest request) {
		for (String forbidden : this.encodedUrlBlacklist) {
			if (encodedUrlContains(request, forbidden)) {
				throw new RequestRejectedException("The request was rejected because the URL contained a potentially malicious String \"" + forbidden + "\"");
			}
		}
		for (String forbidden : this.decodedUrlBlacklist) {
			if (decodedUrlContains(request, forbidden)) {
				throw new RequestRejectedException("The request was rejected because the URL contained a potentially malicious String \"" + forbidden + "\"");
			}
		}
	}

	@Override
	public HttpServletResponse getFirewalledResponse(HttpServletResponse response) {
		return new FirewalledResponse(response);
	}

	private static boolean isNormalized(HttpServletRequest request) {
		if (!isNormalized(request.getRequestURI())) {
			return false;
		}
		if (!isNormalized(request.getContextPath())) {
			return false;
		}
		if (!isNormalized(request.getServletPath())) {
			return false;
		}
		if (!isNormalized(request.getPathInfo())) {
			return false;
		}
		return true;
	}

	private static boolean encodedUrlContains(HttpServletRequest request, String value) {
		if (valueContains(request.getContextPath(), value)) {
			return true;
		}
		return valueContains(request.getRequestURI(), value);
	}

	private static boolean decodedUrlContains(HttpServletRequest request, String value) {
		if (valueContains(request.getServletPath(), value)) {
			return true;
		}
		if (valueContains(request.getPathInfo(), value)) {
			return true;
		}
		return false;
	}

	private static boolean containsOnlyPrintableAsciiCharacters(String uri) {
		int length = uri.length();
		for (int i = 0; i < length; i++) {
			char c = uri.charAt(i);
			if (c < '\u0021' || '\u007e' < c) {
				return false;
			}
		}

		return true;
	}

	private static boolean valueContains(String value, String contains) {
		return value != null && value.contains(contains);
	}

	/**
	 * Checks whether a path is normalized (doesn't contain path traversal
	 * sequences like "./", "/../" or "/.")
	 *
	 * @param path
	 *            the path to test
	 * @return true if the path doesn't contain any path-traversal character
	 *         sequences.
	 */
	private static boolean isNormalized(String path) {
		if (path == null) {
			return true;
		}

		if (path.indexOf("//") > 0) {
			return false;
		}

		for (int j = path.length(); j > 0;) {
			int i = path.lastIndexOf('/', j - 1);
			int gap = j - i;

			if (gap == 2 && path.charAt(i + 1) == '.') {
				// ".", "/./" or "/."
				return false;
			} else if (gap == 3 && path.charAt(i + 1) == '.' && path.charAt(i + 2) == '.') {
				return false;
			}

			j = i;
		}

		return true;
	}

}

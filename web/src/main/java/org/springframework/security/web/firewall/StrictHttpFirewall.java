/*
 * Copyright 2012-2020 the original author or authors.
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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>
 * A strict implementation of {@link HttpFirewall} that rejects any suspicious requests
 * with a {@link RequestRejectedException}.
 * </p>
 * <p>
 * The following rules are applied to the firewall:
 * </p>
 * <ul>
 * <li>
 * Rejects URLs that are not normalized to avoid bypassing security constraints. There is
 * no way to disable this as it is considered extremely risky to disable this constraint.
 * A few options to allow this behavior is to normalize the request prior to the firewall
 * or using {@link DefaultHttpFirewall} instead. Please keep in mind that normalizing the
 * request is fragile and why requests are rejected rather than normalized.
 * </li>
 * <li>
 * Rejects URLs that contain characters that are not printable ASCII characters. There is
 * no way to disable this as it is considered extremely risky to disable this constraint.
 * </li>
 * <li>
 * Rejects URLs that contain semicolons. See {@link #setAllowSemicolon(boolean)}
 * </li>
 * <li>
 * Rejects URLs that contain a URL encoded slash. See
 * {@link #setAllowUrlEncodedSlash(boolean)}
 * </li>
 * <li>
 * Rejects URLs that contain a backslash. See {@link #setAllowBackSlash(boolean)}
 * </li>
 * <li>
 * Rejects URLs that contain a URL encoded percent. See
 * {@link #setAllowUrlEncodedPercent(boolean)}
 * </li>
 * <li>
 * Rejects hosts that are not allowed. See
 * {@link #setAllowedHostnames(Collection)}
 * </li>
 * </ul>
 *
 * @see DefaultHttpFirewall
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 4.2.4
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

	private Collection<String> allowedHostnames;

	public StrictHttpFirewall() {
		urlBlacklistsAddAll(FORBIDDEN_SEMICOLON);
		urlBlacklistsAddAll(FORBIDDEN_FORWARDSLASH);
		urlBlacklistsAddAll(FORBIDDEN_BACKSLASH);

		this.encodedUrlBlacklist.add(ENCODED_PERCENT);
		this.encodedUrlBlacklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		this.decodedUrlBlacklist.add(PERCENT);
	}

	/**
	 * <p>
	 * Determines if semicolon is allowed in the URL (i.e. matrix variables). The default
	 * is to disable this behavior because it is a common way of attempting to perform
	 * <a href="https://www.owasp.org/index.php/Reflected_File_Download">Reflected File Download Attacks</a>.
	 * It is also the source of many exploits which bypass URL based security.
	 * </p>
	 * <p>For example, the following CVEs are a subset of the issues related
	 * to ambiguities in the Servlet Specification on how to treat semicolons that
	 * led to CVEs:
	 * </p>
	 * <ul>
	 *     <li><a href="https://pivotal.io/security/cve-2016-5007">cve-2016-5007</a></li>
	 *     <li><a href="https://pivotal.io/security/cve-2016-9879">cve-2016-9879</a></li>
	 *     <li><a href="https://pivotal.io/security/cve-2018-1199">cve-2018-1199</a></li>
	 * </ul>
	 *
	 * <p>
	 * If you are wanting to allow semicolons, please reconsider as it is a very common
	 * source of security bypasses. A few common reasons users want semicolons and
	 * alternatives are listed below:
	 * </p>
	 * <ul>
	 * <li>Including the JSESSIONID in the path - You should not include session id (or
	 * any sensitive information) in a URL as it can lead to leaking. Instead use Cookies.
	 * </li>
	 * <li>Matrix Variables - Users wanting to leverage Matrix Variables should consider
	 * using HTTP parameters instead.
	 * </li>
	 * </ul>
	 *
	 * @param allowSemicolon should semicolons be allowed in the URL. Default is false
	 */
	public void setAllowSemicolon(boolean allowSemicolon) {
		if (allowSemicolon) {
			urlBlacklistsRemoveAll(FORBIDDEN_SEMICOLON);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_SEMICOLON);
		}
	}

	/**
	 * <p>
	 * Determines if a slash "/" that is URL encoded "%2F" should be allowed in the path
	 * or not. The default is to not allow this behavior because it is a common way to
	 * bypass URL based security.
	 * </p>
	 * <p>
	 * For example, due to ambiguities in the servlet specification, the value is not
	 * parsed consistently which results in different values in {@code HttpServletRequest}
	 * path related values which allow bypassing certain security constraints.
	 * </p>
	 *
	 * @param allowUrlEncodedSlash should a slash "/" that is URL encoded "%2F" be allowed
	 * in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
		if (allowUrlEncodedSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_FORWARDSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_FORWARDSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if a period "." that is URL encoded "%2E" should be allowed in the path
	 * or not. The default is to not allow this behavior because it is a frequent source
	 * of security exploits.
	 * </p>
	 * <p>
	 * For example, due to ambiguities in the servlet specification a URL encoded period
	 * might lead to bypassing security constraints through a directory traversal attack.
	 * This is because the path is not parsed consistently which results  in different
	 * values in {@code HttpServletRequest} path related values which allow bypassing
	 * certain security constraints.
	 * </p>
	 *
	 * @param allowUrlEncodedPeriod should a period "." that is URL encoded "%2E" be
	 * allowed in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedPeriod(boolean allowUrlEncodedPeriod) {
		if (allowUrlEncodedPeriod) {
			this.encodedUrlBlacklist.removeAll(FORBIDDEN_ENCODED_PERIOD);
		} else {
			this.encodedUrlBlacklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		}
	}

	/**
	 * <p>
	 * Determines if a backslash "\" or a URL encoded backslash "%5C" should be allowed in
	 * the path or not. The default is not to allow this behavior because it is a frequent
	 * source of security exploits.
	 * </p>
	 * <p>
	 * For example, due to ambiguities in the servlet specification a URL encoded period
	 * might lead to bypassing security constraints through a directory traversal attack.
	 * This is because the path is not parsed consistently which results  in different
	 * values in {@code HttpServletRequest} path related values which allow bypassing
	 * certain security constraints.
	 * </p>
	 *
	 * @param allowBackSlash a backslash "\" or a URL encoded backslash "%5C" be allowed
	 * in the path or not. Default is false
	 */
	public void setAllowBackSlash(boolean allowBackSlash) {
		if (allowBackSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_BACKSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_BACKSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if a percent "%" that is URL encoded "%25" should be allowed in the path
	 * or not. The default is not to allow this behavior because it is a frequent source
	 * of security exploits.
	 * </p>
	 * <p>
	 * For example, this can lead to exploits that involve double URL encoding that lead
	 * to bypassing security constraints.
	 * </p>
	 *
	 * @param allowUrlEncodedPercent if a percent "%" that is URL encoded "%25" should be
	 * allowed in the path or not. Default is false
	 */
	public void setAllowUrlEncodedPercent(boolean allowUrlEncodedPercent) {
		if (allowUrlEncodedPercent) {
			this.encodedUrlBlacklist.remove(ENCODED_PERCENT);
			this.decodedUrlBlacklist.remove(PERCENT);
		} else {
			this.encodedUrlBlacklist.add(ENCODED_PERCENT);
			this.decodedUrlBlacklist.add(PERCENT);
		}
	}

	/**
	 * <p>
	 * Determines which hostnames should be allowed. The default is to allow any hostname.
	 * </p>
	 *
	 * @param allowedHostnames the set of allowed hostnames
	 * @since 4.2.17
	 */
	public void setAllowedHostnames(Collection<String> allowedHostnames) {
		if (allowedHostnames == null) {
			throw new IllegalArgumentException("allowedHostnames cannot be null");
		}
		this.allowedHostnames = allowedHostnames;
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
		rejectedUntrustedHosts(request);

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

	private void rejectedUntrustedHosts(HttpServletRequest request) {
		String serverName = request.getServerName();
		if (serverName == null) {
			return;
		}
		if (this.allowedHostnames == null) {
			return;
		}
		if (!this.allowedHostnames.contains(serverName)) {
			throw new RequestRejectedException("The request was rejected because the domain " + serverName + " is untrusted.");
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
			if (c < '\u0020' || c > '\u007e') {
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

		if (path.indexOf("//") > -1) {
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

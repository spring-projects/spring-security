/*
 * Copyright 2012-2024 the original author or authors.
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
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.util.Assert;

/**
 * <p>
 * A strict implementation of {@link HttpFirewall} that rejects any suspicious requests
 * with a {@link RequestRejectedException}.
 * </p>
 * <p>
 * The following rules are applied to the firewall:
 * </p>
 * <ul>
 * <li>Rejects HTTP methods that are not allowed. This specified to block
 * <a href="https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)">HTTP Verb
 * tampering and XST attacks</a>. See {@link #setAllowedHttpMethods(Collection)}</li>
 * <li>Rejects URLs that are not normalized to avoid bypassing security constraints. There
 * is no way to disable this as it is considered extremely risky to disable this
 * constraint. A few options to allow this behavior is to normalize the request prior to
 * the firewall or using {@link DefaultHttpFirewall} instead. Please keep in mind that
 * normalizing the request is fragile and why requests are rejected rather than
 * normalized.</li>
 * <li>Rejects URLs that contain characters that are not printable ASCII characters. There
 * is no way to disable this as it is considered extremely risky to disable this
 * constraint.</li>
 * <li>Rejects URLs that contain semicolons. See {@link #setAllowSemicolon(boolean)}</li>
 * <li>Rejects URLs that contain a URL encoded slash. See
 * {@link #setAllowUrlEncodedSlash(boolean)}</li>
 * <li>Rejects URLs that contain a backslash. See {@link #setAllowBackSlash(boolean)}</li>
 * <li>Rejects URLs that contain a null character. See {@link #setAllowNull(boolean)}</li>
 * <li>Rejects URLs that contain a URL encoded percent. See
 * {@link #setAllowUrlEncodedPercent(boolean)}</li>
 * <li>Rejects hosts that are not allowed. See {@link #setAllowedHostnames(Predicate)}
 * </li>
 * <li>Reject headers names that are not allowed. See
 * {@link #setAllowedHeaderNames(Predicate)}</li>
 * <li>Reject headers values that are not allowed. See
 * {@link #setAllowedHeaderValues(Predicate)}</li>
 * <li>Reject parameter names that are not allowed. See
 * {@link #setAllowedParameterNames(Predicate)}</li>
 * <li>Reject parameter values that are not allowed. See
 * {@link #setAllowedParameterValues(Predicate)}</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Jinwoo Bae
 * @since 4.2.4
 * @see DefaultHttpFirewall
 */
public class StrictHttpFirewall implements HttpFirewall {

	/**
	 * Used to specify to {@link #setAllowedHttpMethods(Collection)} that any HTTP method
	 * should be allowed.
	 */
	private static final Set<String> ALLOW_ANY_HTTP_METHOD = Collections.emptySet();

	private static final String ENCODED_PERCENT = "%25";

	private static final String PERCENT = "%";

	private static final List<String> FORBIDDEN_ENCODED_PERIOD = Collections
		.unmodifiableList(Arrays.asList("%2e", "%2E"));

	private static final List<String> FORBIDDEN_SEMICOLON = Collections
		.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));

	private static final List<String> FORBIDDEN_FORWARDSLASH = Collections
		.unmodifiableList(Arrays.asList("%2f", "%2F"));

	private static final List<String> FORBIDDEN_DOUBLE_FORWARDSLASH = Collections
		.unmodifiableList(Arrays.asList("//", "%2f%2f", "%2f%2F", "%2F%2f", "%2F%2F"));

	private static final List<String> FORBIDDEN_BACKSLASH = Collections
		.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));

	private static final List<String> FORBIDDEN_NULL = Collections.unmodifiableList(Arrays.asList("\0", "%00"));

	private static final List<String> FORBIDDEN_LF = Collections.unmodifiableList(Arrays.asList("\n", "%0a", "%0A"));

	private static final List<String> FORBIDDEN_CR = Collections.unmodifiableList(Arrays.asList("\r", "%0d", "%0D"));

	private static final List<String> FORBIDDEN_LINE_SEPARATOR = Collections.unmodifiableList(Arrays.asList("\u2028"));

	private static final List<String> FORBIDDEN_PARAGRAPH_SEPARATOR = Collections
		.unmodifiableList(Arrays.asList("\u2029"));

	private Set<String> encodedUrlBlocklist = new HashSet<>();

	private Set<String> decodedUrlBlocklist = new HashSet<>();

	private Set<String> allowedHttpMethods = createDefaultAllowedHttpMethods();

	private Predicate<String> allowedHostnames = (hostname) -> true;

	private static final Pattern ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN = Pattern
		.compile("[\\p{IsAssigned}&&[^\\p{IsControl}]]*");

	private static final Predicate<String> ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE = (
			s) -> ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN.matcher(s).matches();

	private static final Pattern HEADER_VALUE_PATTERN = Pattern.compile("[\\p{IsAssigned}&&[[^\\p{IsControl}]||\\t]]*");

	private static final Predicate<String> HEADER_VALUE_PREDICATE = (s) -> HEADER_VALUE_PATTERN.matcher(s).matches();

	private Predicate<String> allowedHeaderNames = ALLOWED_HEADER_NAMES;

	public static final Predicate<String> ALLOWED_HEADER_NAMES = ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;

	private Predicate<String> allowedHeaderValues = ALLOWED_HEADER_VALUES;

	public static final Predicate<String> ALLOWED_HEADER_VALUES = HEADER_VALUE_PREDICATE;

	private Predicate<String> allowedParameterNames = ALLOWED_PARAMETER_NAMES;

	public static final Predicate<String> ALLOWED_PARAMETER_NAMES = ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;

	private Predicate<String> allowedParameterValues = ALLOWED_PARAMETER_VALUES;

	public static final Predicate<String> ALLOWED_PARAMETER_VALUES = (value) -> true;

	public StrictHttpFirewall() {
		urlBlocklistsAddAll(FORBIDDEN_SEMICOLON);
		urlBlocklistsAddAll(FORBIDDEN_FORWARDSLASH);
		urlBlocklistsAddAll(FORBIDDEN_DOUBLE_FORWARDSLASH);
		urlBlocklistsAddAll(FORBIDDEN_BACKSLASH);
		urlBlocklistsAddAll(FORBIDDEN_NULL);
		urlBlocklistsAddAll(FORBIDDEN_LF);
		urlBlocklistsAddAll(FORBIDDEN_CR);

		this.encodedUrlBlocklist.add(ENCODED_PERCENT);
		this.encodedUrlBlocklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		this.decodedUrlBlocklist.add(PERCENT);
		this.decodedUrlBlocklist.addAll(FORBIDDEN_LINE_SEPARATOR);
		this.decodedUrlBlocklist.addAll(FORBIDDEN_PARAGRAPH_SEPARATOR);
	}

	/**
	 * Sets if any HTTP method is allowed. If this set to true, then no validation on the
	 * HTTP method will be performed. This can open the application up to
	 * <a href="https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)"> HTTP
	 * Verb tampering and XST attacks</a>
	 * @param unsafeAllowAnyHttpMethod if true, disables HTTP method validation, else
	 * resets back to the defaults. Default is false.
	 * @since 5.1
	 * @see #setAllowedHttpMethods(Collection)
	 */
	public void setUnsafeAllowAnyHttpMethod(boolean unsafeAllowAnyHttpMethod) {
		this.allowedHttpMethods = unsafeAllowAnyHttpMethod ? ALLOW_ANY_HTTP_METHOD : createDefaultAllowedHttpMethods();
	}

	/**
	 * <p>
	 * Determines which HTTP methods should be allowed. The default is to allow "DELETE",
	 * "GET", "HEAD", "OPTIONS", "PATCH", "POST", and "PUT".
	 * </p>
	 * @param allowedHttpMethods the case-sensitive collection of HTTP methods that are
	 * allowed.
	 * @since 5.1
	 * @see #setUnsafeAllowAnyHttpMethod(boolean)
	 */
	public void setAllowedHttpMethods(Collection<String> allowedHttpMethods) {
		Assert.notNull(allowedHttpMethods, "allowedHttpMethods cannot be null");
		this.allowedHttpMethods = (allowedHttpMethods != ALLOW_ANY_HTTP_METHOD) ? new HashSet<>(allowedHttpMethods)
				: ALLOW_ANY_HTTP_METHOD;
	}

	/**
	 * <p>
	 * Determines if semicolon is allowed in the URL (i.e. matrix variables). The default
	 * is to disable this behavior because it is a common way of attempting to perform
	 * <a href="https://www.owasp.org/index.php/Reflected_File_Download">Reflected File
	 * Download Attacks</a>. It is also the source of many exploits which bypass URL based
	 * security.
	 * </p>
	 * <p>
	 * For example, the following CVEs are a subset of the issues related to ambiguities
	 * in the Servlet Specification on how to treat semicolons that led to CVEs:
	 * </p>
	 * <ul>
	 * <li><a href="https://pivotal.io/security/cve-2016-5007">cve-2016-5007</a></li>
	 * <li><a href="https://pivotal.io/security/cve-2016-9879">cve-2016-9879</a></li>
	 * <li><a href="https://pivotal.io/security/cve-2018-1199">cve-2018-1199</a></li>
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
	 * using HTTP parameters instead.</li>
	 * </ul>
	 * @param allowSemicolon should semicolons be allowed in the URL. Default is false
	 */
	public void setAllowSemicolon(boolean allowSemicolon) {
		if (allowSemicolon) {
			urlBlocklistsRemoveAll(FORBIDDEN_SEMICOLON);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_SEMICOLON);
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
	 * @param allowUrlEncodedSlash should a slash "/" that is URL encoded "%2F" be allowed
	 * in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
		if (allowUrlEncodedSlash) {
			urlBlocklistsRemoveAll(FORBIDDEN_FORWARDSLASH);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_FORWARDSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if double slash "//" that is URL encoded "%2F%2F" should be allowed in
	 * the path or not. The default is to not allow.
	 * </p>
	 * @param allowUrlEncodedDoubleSlash should a slash "//" that is URL encoded "%2F%2F"
	 * be allowed in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedDoubleSlash(boolean allowUrlEncodedDoubleSlash) {
		if (allowUrlEncodedDoubleSlash) {
			urlBlocklistsRemoveAll(FORBIDDEN_DOUBLE_FORWARDSLASH);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_DOUBLE_FORWARDSLASH);
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
	 * This is because the path is not parsed consistently which results in different
	 * values in {@code HttpServletRequest} path related values which allow bypassing
	 * certain security constraints.
	 * </p>
	 * @param allowUrlEncodedPeriod should a period "." that is URL encoded "%2E" be
	 * allowed in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedPeriod(boolean allowUrlEncodedPeriod) {
		if (allowUrlEncodedPeriod) {
			this.encodedUrlBlocklist.removeAll(FORBIDDEN_ENCODED_PERIOD);
		}
		else {
			this.encodedUrlBlocklist.addAll(FORBIDDEN_ENCODED_PERIOD);
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
	 * This is because the path is not parsed consistently which results in different
	 * values in {@code HttpServletRequest} path related values which allow bypassing
	 * certain security constraints.
	 * </p>
	 * @param allowBackSlash a backslash "\" or a URL encoded backslash "%5C" be allowed
	 * in the path or not. Default is false
	 */
	public void setAllowBackSlash(boolean allowBackSlash) {
		if (allowBackSlash) {
			urlBlocklistsRemoveAll(FORBIDDEN_BACKSLASH);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_BACKSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if a null "\0" or a URL encoded nul "%00" should be allowed in the path
	 * or not. The default is not to allow this behavior because it is a frequent source
	 * of security exploits.
	 * </p>
	 * @param allowNull a null "\0" or a URL encoded null "%00" be allowed in the path or
	 * not. Default is false
	 * @since 5.4
	 */
	public void setAllowNull(boolean allowNull) {
		if (allowNull) {
			urlBlocklistsRemoveAll(FORBIDDEN_NULL);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_NULL);
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
	 * @param allowUrlEncodedPercent if a percent "%" that is URL encoded "%25" should be
	 * allowed in the path or not. Default is false
	 */
	public void setAllowUrlEncodedPercent(boolean allowUrlEncodedPercent) {
		if (allowUrlEncodedPercent) {
			this.encodedUrlBlocklist.remove(ENCODED_PERCENT);
			this.decodedUrlBlocklist.remove(PERCENT);
		}
		else {
			this.encodedUrlBlocklist.add(ENCODED_PERCENT);
			this.decodedUrlBlocklist.add(PERCENT);
		}
	}

	/**
	 * Determines if a URL encoded Carriage Return is allowed in the path or not. The
	 * default is not to allow this behavior because it is a frequent source of security
	 * exploits.
	 * @param allowUrlEncodedCarriageReturn if URL encoded Carriage Return is allowed in
	 * the URL or not. Default is false.
	 */
	public void setAllowUrlEncodedCarriageReturn(boolean allowUrlEncodedCarriageReturn) {
		if (allowUrlEncodedCarriageReturn) {
			urlBlocklistsRemoveAll(FORBIDDEN_CR);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_CR);
		}
	}

	/**
	 * Determines if a URL encoded Line Feed is allowed in the path or not. The default is
	 * not to allow this behavior because it is a frequent source of security exploits.
	 * @param allowUrlEncodedLineFeed if URL encoded Line Feed is allowed in the URL or
	 * not. Default is false.
	 */
	public void setAllowUrlEncodedLineFeed(boolean allowUrlEncodedLineFeed) {
		if (allowUrlEncodedLineFeed) {
			urlBlocklistsRemoveAll(FORBIDDEN_LF);
		}
		else {
			urlBlocklistsAddAll(FORBIDDEN_LF);
		}
	}

	/**
	 * Determines if a URL encoded paragraph separator is allowed in the path or not. The
	 * default is not to allow this behavior because it is a frequent source of security
	 * exploits.
	 * @param allowUrlEncodedParagraphSeparator if URL encoded paragraph separator is
	 * allowed in the URL or not. Default is false.
	 */
	public void setAllowUrlEncodedParagraphSeparator(boolean allowUrlEncodedParagraphSeparator) {
		if (allowUrlEncodedParagraphSeparator) {
			this.decodedUrlBlocklist.removeAll(FORBIDDEN_PARAGRAPH_SEPARATOR);
		}
		else {
			this.decodedUrlBlocklist.addAll(FORBIDDEN_PARAGRAPH_SEPARATOR);
		}
	}

	/**
	 * Determines if a URL encoded line separator is allowed in the path or not. The
	 * default is not to allow this behavior because it is a frequent source of security
	 * exploits.
	 * @param allowUrlEncodedLineSeparator if URL encoded line separator is allowed in the
	 * URL or not. Default is false.
	 */
	public void setAllowUrlEncodedLineSeparator(boolean allowUrlEncodedLineSeparator) {
		if (allowUrlEncodedLineSeparator) {
			this.decodedUrlBlocklist.removeAll(FORBIDDEN_LINE_SEPARATOR);
		}
		else {
			this.decodedUrlBlocklist.addAll(FORBIDDEN_LINE_SEPARATOR);
		}
	}

	/**
	 * <p>
	 * Determines which header names should be allowed. The default is to reject header
	 * names that contain ISO control characters and characters that are not defined.
	 * </p>
	 * @param allowedHeaderNames the predicate for testing header names
	 * @since 5.4
	 * @see Character#isISOControl(int)
	 * @see Character#isDefined(int)
	 */
	public void setAllowedHeaderNames(Predicate<String> allowedHeaderNames) {
		Assert.notNull(allowedHeaderNames, "allowedHeaderNames cannot be null");
		this.allowedHeaderNames = allowedHeaderNames;
	}

	/**
	 * <p>
	 * Determines which header values should be allowed. The default is to reject header
	 * values that contain ISO control characters and characters that are not defined.
	 * </p>
	 * @param allowedHeaderValues the predicate for testing hostnames
	 * @since 5.4
	 * @see Character#isISOControl(int)
	 * @see Character#isDefined(int)
	 */
	public void setAllowedHeaderValues(Predicate<String> allowedHeaderValues) {
		Assert.notNull(allowedHeaderValues, "allowedHeaderValues cannot be null");
		this.allowedHeaderValues = allowedHeaderValues;
	}

	/**
	 * Determines which parameter names should be allowed. The default is to reject header
	 * names that contain ISO control characters and characters that are not defined.
	 * @param allowedParameterNames the predicate for testing parameter names
	 * @since 5.4
	 * @see Character#isISOControl(int)
	 * @see Character#isDefined(int)
	 */
	public void setAllowedParameterNames(Predicate<String> allowedParameterNames) {
		Assert.notNull(allowedParameterNames, "allowedParameterNames cannot be null");
		this.allowedParameterNames = allowedParameterNames;
	}

	/**
	 * <p>
	 * Determines which parameter values should be allowed. The default is to allow any
	 * parameter value.
	 * </p>
	 * @param allowedParameterValues the predicate for testing parameter values
	 * @since 5.4
	 */
	public void setAllowedParameterValues(Predicate<String> allowedParameterValues) {
		Assert.notNull(allowedParameterValues, "allowedParameterValues cannot be null");
		this.allowedParameterValues = allowedParameterValues;
	}

	/**
	 * <p>
	 * Determines which hostnames should be allowed. The default is to allow any hostname.
	 * </p>
	 * @param allowedHostnames the predicate for testing hostnames
	 * @since 5.2
	 */
	public void setAllowedHostnames(Predicate<String> allowedHostnames) {
		Assert.notNull(allowedHostnames, "allowedHostnames cannot be null");
		this.allowedHostnames = allowedHostnames;
	}

	private void urlBlocklistsAddAll(Collection<String> values) {
		this.encodedUrlBlocklist.addAll(values);
		this.decodedUrlBlocklist.addAll(values);
	}

	private void urlBlocklistsRemoveAll(Collection<String> values) {
		this.encodedUrlBlocklist.removeAll(values);
		this.decodedUrlBlocklist.removeAll(values);
	}

	@Override
	public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
		rejectForbiddenHttpMethod(request);
		rejectedBlocklistedUrls(request);
		rejectedUntrustedHosts(request);
		if (!isNormalized(request)) {
			throw new RequestRejectedException("The request was rejected because the URL was not normalized.");
		}
		rejectNonPrintableAsciiCharactersInFieldName(request.getRequestURI(), "requestURI");
		return new StrictFirewalledRequest(request);
	}

	private void rejectNonPrintableAsciiCharactersInFieldName(String toCheck, String propertyName) {
		if (!containsOnlyPrintableAsciiCharacters(toCheck)) {
			throw new RequestRejectedException(String
				.format("The %s was rejected because it can only contain printable ASCII characters.", propertyName));
		}
	}

	private void rejectForbiddenHttpMethod(HttpServletRequest request) {
		if (this.allowedHttpMethods == ALLOW_ANY_HTTP_METHOD) {
			return;
		}
		if (!this.allowedHttpMethods.contains(request.getMethod())) {
			throw new RequestRejectedException(
					"The request was rejected because the HTTP method \"" + request.getMethod()
							+ "\" was not included within the list of allowed HTTP methods " + this.allowedHttpMethods);
		}
	}

	private void rejectedBlocklistedUrls(HttpServletRequest request) {
		for (String forbidden : this.encodedUrlBlocklist) {
			if (encodedUrlContains(request, forbidden)) {
				throw new RequestRejectedException(
						"The request was rejected because the URL contained a potentially malicious String \""
								+ forbidden + "\"");
			}
		}
		for (String forbidden : this.decodedUrlBlocklist) {
			if (decodedUrlContains(request, forbidden)) {
				throw new RequestRejectedException(
						"The request was rejected because the URL contained a potentially malicious String \""
								+ forbidden + "\"");
			}
		}
	}

	private void rejectedUntrustedHosts(HttpServletRequest request) {
		String serverName = request.getServerName();
		if (serverName != null && !this.allowedHostnames.test(serverName)) {
			throw new RequestRejectedException(
					"The request was rejected because the domain " + serverName + " is untrusted.");
		}
	}

	@Override
	public HttpServletResponse getFirewalledResponse(HttpServletResponse response) {
		return new FirewalledResponse(response);
	}

	private static Set<String> createDefaultAllowedHttpMethods() {
		Set<String> result = new HashSet<>();
		result.add(HttpMethod.DELETE.name());
		result.add(HttpMethod.GET.name());
		result.add(HttpMethod.HEAD.name());
		result.add(HttpMethod.OPTIONS.name());
		result.add(HttpMethod.PATCH.name());
		result.add(HttpMethod.POST.name());
		result.add(HttpMethod.PUT.name());
		return result;
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
		return valueContains(request.getPathInfo(), value);
	}

	private static boolean containsOnlyPrintableAsciiCharacters(String uri) {
		if (uri == null) {
			return true;
		}
		int length = uri.length();
		for (int i = 0; i < length; i++) {
			char ch = uri.charAt(i);
			if (ch < '\u0020' || ch > '\u007e') {
				return false;
			}
		}
		return true;
	}

	private static boolean valueContains(String value, String contains) {
		return value != null && value.contains(contains);
	}

	/**
	 * Checks whether a path is normalized (doesn't contain path traversal sequences like
	 * "./", "/../" or "/.")
	 * @param path the path to test
	 * @return true if the path doesn't contain any path-traversal character sequences.
	 */
	private static boolean isNormalized(String path) {
		if (path == null) {
			return true;
		}
		for (int i = path.length(); i > 0;) {
			int slashIndex = path.lastIndexOf('/', i - 1);
			int gap = i - slashIndex;
			if (gap == 2 && path.charAt(slashIndex + 1) == '.') {
				return false; // ".", "/./" or "/."
			}
			if (gap == 3 && path.charAt(slashIndex + 1) == '.' && path.charAt(slashIndex + 2) == '.') {
				return false;
			}
			i = slashIndex;
		}
		return true;
	}

	/**
	 * Provides the existing encoded url blocklist which can add/remove entries from
	 * @return the existing encoded url blocklist, never null
	 */
	public Set<String> getEncodedUrlBlocklist() {
		return this.encodedUrlBlocklist;
	}

	/**
	 * Provides the existing decoded url blocklist which can add/remove entries from
	 * @return the existing decoded url blocklist, never null
	 */
	public Set<String> getDecodedUrlBlocklist() {
		return this.decodedUrlBlocklist;
	}

	/**
	 * Provides the existing encoded url blocklist which can add/remove entries from
	 * @return the existing encoded url blocklist, never null
	 * @deprecated Use {@link #getEncodedUrlBlocklist()} instead
	 */
	@Deprecated
	public Set<String> getEncodedUrlBlacklist() {
		return getEncodedUrlBlocklist();
	}

	/**
	 * Provides the existing decoded url blocklist which can add/remove entries from
	 * @return the existing decoded url blocklist, never null
	 *
	 */
	public Set<String> getDecodedUrlBlacklist() {
		return getDecodedUrlBlocklist();
	}

	/**
	 * Strict {@link FirewalledRequest}.
	 */
	private class StrictFirewalledRequest extends FirewalledRequest {

		StrictFirewalledRequest(HttpServletRequest request) {
			super(request);
		}

		@Override
		public long getDateHeader(String name) {
			if (name != null) {
				validateAllowedHeaderName(name);
			}
			return super.getDateHeader(name);
		}

		@Override
		public int getIntHeader(String name) {
			if (name != null) {
				validateAllowedHeaderName(name);
			}
			return super.getIntHeader(name);
		}

		@Override
		public String getHeader(String name) {
			if (name != null) {
				validateAllowedHeaderName(name);
			}
			String value = super.getHeader(name);
			if (value != null) {
				validateAllowedHeaderValue(name, value);
			}
			return value;
		}

		@Override
		public Enumeration<String> getHeaders(String name) {
			if (name != null) {
				validateAllowedHeaderName(name);
			}
			Enumeration<String> headers = super.getHeaders(name);
			return new Enumeration<>() {

				@Override
				public boolean hasMoreElements() {
					return headers.hasMoreElements();
				}

				@Override
				public String nextElement() {
					String value = headers.nextElement();
					validateAllowedHeaderValue(name, value);
					return value;
				}

			};
		}

		@Override
		public Enumeration<String> getHeaderNames() {
			Enumeration<String> names = super.getHeaderNames();
			return new Enumeration<>() {

				@Override
				public boolean hasMoreElements() {
					return names.hasMoreElements();
				}

				@Override
				public String nextElement() {
					String headerNames = names.nextElement();
					validateAllowedHeaderName(headerNames);
					return headerNames;
				}

			};
		}

		@Override
		public String getParameter(String name) {
			if (name != null) {
				validateAllowedParameterName(name);
			}
			String value = super.getParameter(name);
			if (value != null) {
				validateAllowedParameterValue(name, value);
			}
			return value;
		}

		@Override
		public Map<String, String[]> getParameterMap() {
			Map<String, String[]> parameterMap = super.getParameterMap();
			for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
				String name = entry.getKey();
				String[] values = entry.getValue();
				validateAllowedParameterName(name);
				for (String value : values) {
					validateAllowedParameterValue(name, value);
				}
			}
			return parameterMap;
		}

		@Override
		public Enumeration<String> getParameterNames() {
			Enumeration<String> paramaterNames = super.getParameterNames();
			return new Enumeration<>() {

				@Override
				public boolean hasMoreElements() {
					return paramaterNames.hasMoreElements();
				}

				@Override
				public String nextElement() {
					String name = paramaterNames.nextElement();
					validateAllowedParameterName(name);
					return name;
				}

			};
		}

		@Override
		public String[] getParameterValues(String name) {
			if (name != null) {
				validateAllowedParameterName(name);
			}
			String[] values = super.getParameterValues(name);
			if (values != null) {
				for (String value : values) {
					validateAllowedParameterValue(name, value);
				}
			}
			return values;
		}

		private void validateAllowedHeaderName(String headerNames) {
			if (!StrictHttpFirewall.this.allowedHeaderNames.test(headerNames)) {
				throw new RequestRejectedException(
						"The request was rejected because the header name \"" + headerNames + "\" is not allowed.");
			}
		}

		private void validateAllowedHeaderValue(String name, String value) {
			if (!StrictHttpFirewall.this.allowedHeaderValues.test(value)) {
				throw new RequestRejectedException("The request was rejected because the header: \"" + name
						+ " \" has a value \"" + value + "\" that is not allowed.");
			}
		}

		private void validateAllowedParameterName(String name) {
			if (!StrictHttpFirewall.this.allowedParameterNames.test(name)) {
				throw new RequestRejectedException(
						"The request was rejected because the parameter name \"" + name + "\" is not allowed.");
			}
		}

		private void validateAllowedParameterValue(String name, String value) {
			if (!StrictHttpFirewall.this.allowedParameterValues.test(value)) {
				throw new RequestRejectedException("The request was rejected because the parameter: \"" + name
						+ " \" has a value \"" + value + "\" that is not allowed.");
			}
		}

		@Override
		public void reset() {
		}

	};

}

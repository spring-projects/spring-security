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

package org.springframework.security.web.server.firewall;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;

/**
 * <p>
 * A strict implementation of {@link ServerWebExchangeFirewall} that rejects any
 * suspicious requests with a {@link ServerExchangeRejectedException}.
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
 * the firewall or using
 * {@link org.springframework.security.web.firewall.DefaultHttpFirewall} instead. Please
 * keep in mind that normalizing the request is fragile and why requests are rejected
 * rather than normalized.</li>
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
 * @since 6.4
 */
public class StrictServerWebExchangeFirewall implements ServerWebExchangeFirewall {

	/**
	 * Used to specify to {@link #setAllowedHttpMethods(Collection)} that any HTTP method
	 * should be allowed.
	 */
	private static final Set<HttpMethod> ALLOW_ANY_HTTP_METHOD = Collections.emptySet();

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

	private Set<HttpMethod> allowedHttpMethods = createDefaultAllowedHttpMethods();

	private Predicate<String> allowedHostnames = (hostname) -> true;

	private static final Pattern ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN = Pattern
		.compile("[\\p{IsAssigned}&&[^\\p{IsControl}]]*");

	private static final Predicate<String> ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE = (
			s) -> ASSIGNED_AND_NOT_ISO_CONTROL_PATTERN.matcher(s).matches();

	private static final Pattern HEADER_VALUE_PATTERN = Pattern.compile("[\\p{IsAssigned}&&[[^\\p{IsControl}]||\\t]]*");

	private static final Predicate<String> HEADER_VALUE_PREDICATE = (s) -> s == null
			|| HEADER_VALUE_PATTERN.matcher(s).matches();

	private Predicate<String> allowedHeaderNames = ALLOWED_HEADER_NAMES;

	public static final Predicate<String> ALLOWED_HEADER_NAMES = ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;

	private Predicate<String> allowedHeaderValues = ALLOWED_HEADER_VALUES;

	public static final Predicate<String> ALLOWED_HEADER_VALUES = HEADER_VALUE_PREDICATE;

	private Predicate<String> allowedParameterNames = ALLOWED_PARAMETER_NAMES;

	public static final Predicate<String> ALLOWED_PARAMETER_NAMES = ASSIGNED_AND_NOT_ISO_CONTROL_PREDICATE;

	private Predicate<String> allowedParameterValues = ALLOWED_PARAMETER_VALUES;

	public static final Predicate<String> ALLOWED_PARAMETER_VALUES = (value) -> true;

	public StrictServerWebExchangeFirewall() {
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

	public Set<String> getEncodedUrlBlocklist() {
		return this.encodedUrlBlocklist;
	}

	public Set<String> getDecodedUrlBlocklist() {
		return this.decodedUrlBlocklist;
	}

	@Override
	public Mono<ServerWebExchange> getFirewalledExchange(ServerWebExchange exchange) {
		return Mono.fromCallable(() -> {
			ServerHttpRequest request = exchange.getRequest();
			rejectForbiddenHttpMethod(request);
			rejectedBlocklistedUrls(request);
			rejectedUntrustedHosts(request);
			if (!isNormalized(request)) {
				throw new ServerExchangeRejectedException(
						"The request was rejected because the URL was not normalized");
			}

			exchange.getResponse().beforeCommit(() -> Mono.fromRunnable(() -> {
				ServerHttpResponse response = exchange.getResponse();
				HttpHeaders headers = response.getHeaders();
				for (Map.Entry<String, List<String>> header : headers.entrySet()) {
					String headerName = header.getKey();
					List<String> headerValues = header.getValue();
					for (String headerValue : headerValues) {
						validateCrlf(headerName, headerValue);
					}
				}
			}));
			return new StrictFirewallServerWebExchange(exchange);
		});
	}

	private static void validateCrlf(String name, String value) {
		Assert.isTrue(!hasCrlf(name) && !hasCrlf(value), () -> "Invalid characters (CR/LF) in header " + name);
	}

	private static boolean hasCrlf(String value) {
		return value != null && (value.indexOf('\n') != -1 || value.indexOf('\r') != -1);
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
	public void setAllowedHttpMethods(Collection<HttpMethod> allowedHttpMethods) {
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

	private void rejectNonPrintableAsciiCharactersInFieldName(String toCheck, String propertyName) {
		if (!containsOnlyPrintableAsciiCharacters(toCheck)) {
			throw new ServerExchangeRejectedException(String
				.format("The %s was rejected because it can only contain printable ASCII characters.", propertyName));
		}
	}

	private void rejectForbiddenHttpMethod(ServerHttpRequest request) {
		if (this.allowedHttpMethods == ALLOW_ANY_HTTP_METHOD) {
			return;
		}
		if (!this.allowedHttpMethods.contains(request.getMethod())) {
			throw new ServerExchangeRejectedException(
					"The request was rejected because the HTTP method \"" + request.getMethod()
							+ "\" was not included within the list of allowed HTTP methods " + this.allowedHttpMethods);
		}
	}

	private void rejectedBlocklistedUrls(ServerHttpRequest request) {
		for (String forbidden : this.encodedUrlBlocklist) {
			if (encodedUrlContains(request, forbidden)) {
				throw new ServerExchangeRejectedException(
						"The request was rejected because the URL contained a potentially malicious String \""
								+ forbidden + "\"");
			}
		}
		for (String forbidden : this.decodedUrlBlocklist) {
			if (decodedUrlContains(request, forbidden)) {
				throw new ServerExchangeRejectedException(
						"The request was rejected because the URL contained a potentially malicious String \""
								+ forbidden + "\"");
			}
		}
	}

	private void rejectedUntrustedHosts(ServerHttpRequest request) {
		String hostName = request.getURI().getHost();
		if (hostName != null && !this.allowedHostnames.test(hostName)) {
			throw new ServerExchangeRejectedException(
					"The request was rejected because the domain " + hostName + " is untrusted.");
		}
	}

	private static Set<HttpMethod> createDefaultAllowedHttpMethods() {
		Set<HttpMethod> result = new HashSet<>();
		result.add(HttpMethod.DELETE);
		result.add(HttpMethod.GET);
		result.add(HttpMethod.HEAD);
		result.add(HttpMethod.OPTIONS);
		result.add(HttpMethod.PATCH);
		result.add(HttpMethod.POST);
		result.add(HttpMethod.PUT);
		return result;
	}

	private boolean isNormalized(ServerHttpRequest request) {
		if (!isNormalized(request.getPath().value())) {
			return false;
		}
		if (!isNormalized(request.getURI().getRawPath())) {
			return false;
		}
		if (!isNormalized(request.getURI().getPath())) {
			return false;
		}
		return true;
	}

	private void validateAllowedHeaderName(String headerNames) {
		if (!StrictServerWebExchangeFirewall.this.allowedHeaderNames.test(headerNames)) {
			throw new ServerExchangeRejectedException(
					"The request was rejected because the header name \"" + headerNames + "\" is not allowed.");
		}
	}

	private void validateAllowedHeaderValue(Object key, String value) {
		if (!StrictServerWebExchangeFirewall.this.allowedHeaderValues.test(value)) {
			throw new ServerExchangeRejectedException("The request was rejected because the header: \"" + key
					+ " \" has a value \"" + value + "\" that is not allowed.");
		}
	}

	private void validateAllowedParameterName(String name) {
		if (!StrictServerWebExchangeFirewall.this.allowedParameterNames.test(name)) {
			throw new ServerExchangeRejectedException(
					"The request was rejected because the parameter name \"" + name + "\" is not allowed.");
		}
	}

	private void validateAllowedParameterValue(String name, String value) {
		if (!StrictServerWebExchangeFirewall.this.allowedParameterValues.test(value)) {
			throw new ServerExchangeRejectedException("The request was rejected because the parameter: \"" + name
					+ " \" has a value \"" + value + "\" that is not allowed.");
		}
	}

	private static boolean encodedUrlContains(ServerHttpRequest request, String value) {
		if (valueContains(request.getPath().value(), value)) {
			return true;
		}
		return valueContains(request.getURI().getRawPath(), value);
	}

	private static boolean decodedUrlContains(ServerHttpRequest request, String value) {
		return valueContains(request.getURI().getPath(), value);
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

	private final class StrictFirewallServerWebExchange extends ServerWebExchangeDecorator {

		private StrictFirewallServerWebExchange(ServerWebExchange delegate) {
			super(delegate);
		}

		@Override
		public ServerHttpRequest getRequest() {
			return new StrictFirewallHttpRequest(super.getRequest());
		}

		private final class StrictFirewallHttpRequest extends ServerHttpRequestDecorator {

			private StrictFirewallHttpRequest(ServerHttpRequest delegate) {
				super(delegate);
			}

			@Override
			public HttpHeaders getHeaders() {
				return new StrictFirewallHttpHeaders(super.getHeaders());
			}

			@Override
			public MultiValueMap<String, String> getQueryParams() {
				MultiValueMap<String, String> queryParams = super.getQueryParams();
				for (Map.Entry<String, List<String>> paramEntry : queryParams.entrySet()) {
					String paramName = paramEntry.getKey();
					validateAllowedParameterName(paramName);
					for (String paramValue : paramEntry.getValue()) {
						validateAllowedParameterValue(paramName, paramValue);
					}
				}
				return queryParams;
			}

			@Override
			public Builder mutate() {
				return new StrictFirewallBuilder(super.mutate());
			}

			private final class StrictFirewallHttpHeaders extends HttpHeaders {

				private StrictFirewallHttpHeaders(HttpHeaders delegate) {
					super(delegate);
				}

				@Override
				public String getFirst(String headerName) {
					validateAllowedHeaderName(headerName);
					String headerValue = super.getFirst(headerName);
					validateAllowedHeaderValue(headerName, headerValue);
					return headerValue;
				}

				@Override
				public List<String> get(Object key) {
					if (key instanceof String headerName) {
						validateAllowedHeaderName(headerName);
					}
					List<String> headerValues = super.get(key);
					if (headerValues == null) {
						return headerValues;
					}
					for (String headerValue : headerValues) {
						validateAllowedHeaderValue(key, headerValue);
					}
					return headerValues;
				}

				@Override
				public Set<String> keySet() {
					Set<String> headerNames = super.keySet();
					for (String headerName : headerNames) {
						validateAllowedHeaderName(headerName);
					}
					return headerNames;
				}

			}

			private final class StrictFirewallBuilder implements Builder {

				private final Builder delegate;

				private StrictFirewallBuilder(Builder delegate) {
					this.delegate = delegate;
				}

				@Override
				public Builder method(HttpMethod httpMethod) {
					return this.delegate.method(httpMethod);
				}

				@Override
				public Builder uri(URI uri) {
					return this.delegate.uri(uri);
				}

				@Override
				public Builder path(String path) {
					return this.delegate.path(path);
				}

				@Override
				public Builder contextPath(String contextPath) {
					return this.delegate.contextPath(contextPath);
				}

				@Override
				public Builder header(String headerName, String... headerValues) {
					return this.delegate.header(headerName, headerValues);
				}

				@Override
				public Builder headers(Consumer<HttpHeaders> headersConsumer) {
					return this.delegate.headers(headersConsumer);
				}

				@Override
				public Builder sslInfo(SslInfo sslInfo) {
					return this.delegate.sslInfo(sslInfo);
				}

				@Override
				public Builder remoteAddress(InetSocketAddress remoteAddress) {
					return this.delegate.remoteAddress(remoteAddress);
				}

				@Override
				public ServerHttpRequest build() {
					return new StrictFirewallHttpRequest(this.delegate.build());
				}

			}

		}

	}

}

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

package org.springframework.security.web.savedrequest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Represents central information from a {@code HttpServletRequest}.
 * <p>
 * This class is used by
 * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter}
 * and {@link org.springframework.security.web.savedrequest.SavedRequestAwareWrapper} to
 * reproduce the request after successful authentication. An instance of this class is
 * stored at the time of an authentication exception by
 * {@link org.springframework.security.web.access.ExceptionTranslationFilter}.
 * <p>
 * <em>IMPLEMENTATION NOTE</em>: It is assumed that this object is accessed only from the
 * context of a single thread, so no synchronization around internal collection classes is
 * performed.
 * <p>
 * This class is based on code in Apache Tomcat.
 *
 * @author Craig McClanahan
 * @author Andrey Grebnev
 * @author Ben Alex
 * @author Luke Taylor
 */
public class DefaultSavedRequest implements SavedRequest {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	protected static final Log logger = LogFactory.getLog(DefaultSavedRequest.class);

	private static final String HEADER_IF_NONE_MATCH = "If-None-Match";

	private static final String HEADER_IF_MODIFIED_SINCE = "If-Modified-Since";

	private final ArrayList<SavedCookie> cookies = new ArrayList<>();

	private final ArrayList<Locale> locales = new ArrayList<>();

	private final Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

	private final Map<String, String[]> parameters = new TreeMap<>();

	private final String contextPath;

	private final String method;

	private final String pathInfo;

	private final String queryString;

	private final String requestURI;

	private final String requestURL;

	private final String scheme;

	private final String serverName;

	private final String servletPath;

	private final int serverPort;

	private final String matchingRequestParameterName;

	public DefaultSavedRequest(HttpServletRequest request, PortResolver portResolver) {
		this(request, portResolver, null);
	}

	@SuppressWarnings("unchecked")
	public DefaultSavedRequest(HttpServletRequest request, PortResolver portResolver,
			String matchingRequestParameterName) {
		Assert.notNull(request, "Request required");
		Assert.notNull(portResolver, "PortResolver required");
		// Cookies
		addCookies(request.getCookies());
		// Headers
		Enumeration<String> names = request.getHeaderNames();
		while (names.hasMoreElements()) {
			String name = names.nextElement();
			// Skip If-Modified-Since and If-None-Match header. SEC-1412, SEC-1624.
			if (HEADER_IF_MODIFIED_SINCE.equalsIgnoreCase(name) || HEADER_IF_NONE_MATCH.equalsIgnoreCase(name)) {
				continue;
			}
			Enumeration<String> values = request.getHeaders(name);
			while (values.hasMoreElements()) {
				this.addHeader(name, values.nextElement());
			}
		}
		// Locales
		addLocales(request.getLocales());
		// Parameters
		addParameters(request.getParameterMap());
		// Primitives
		this.method = request.getMethod();
		this.pathInfo = request.getPathInfo();
		this.queryString = request.getQueryString();
		this.requestURI = request.getRequestURI();
		this.serverPort = portResolver.getServerPort(request);
		this.requestURL = request.getRequestURL().toString();
		this.scheme = request.getScheme();
		this.serverName = request.getServerName();
		this.contextPath = request.getContextPath();
		this.servletPath = request.getServletPath();
		this.matchingRequestParameterName = matchingRequestParameterName;
	}

	/**
	 * Private constructor invoked through Builder
	 */
	private DefaultSavedRequest(Builder builder) {
		this.contextPath = builder.contextPath;
		this.method = builder.method;
		this.pathInfo = builder.pathInfo;
		this.queryString = builder.queryString;
		this.requestURI = builder.requestURI;
		this.requestURL = builder.requestURL;
		this.scheme = builder.scheme;
		this.serverName = builder.serverName;
		this.servletPath = builder.servletPath;
		this.serverPort = builder.serverPort;
		this.matchingRequestParameterName = builder.matchingRequestParameterName;
	}

	/**
	 * @since 4.2
	 */
	private void addCookies(Cookie[] cookies) {
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				this.addCookie(cookie);
			}
		}
	}

	private void addCookie(Cookie cookie) {
		this.cookies.add(new SavedCookie(cookie));
	}

	private void addHeader(String name, String value) {
		List<String> values = this.headers.computeIfAbsent(name, (key) -> new ArrayList<>());
		values.add(value);
	}

	/**
	 * @since 4.2
	 */
	private void addLocales(Enumeration<Locale> locales) {
		while (locales.hasMoreElements()) {
			Locale locale = locales.nextElement();
			this.addLocale(locale);
		}
	}

	private void addLocale(Locale locale) {
		this.locales.add(locale);
	}

	/**
	 * @since 4.2
	 */
	private void addParameters(Map<String, String[]> parameters) {
		if (!ObjectUtils.isEmpty(parameters)) {
			for (String paramName : parameters.keySet()) {
				Object paramValues = parameters.get(paramName);
				if (paramValues instanceof String[]) {
					this.addParameter(paramName, (String[]) paramValues);
				}
				else {
					logger.warn("ServletRequest.getParameterMap() returned non-String array");
				}
			}
		}
	}

	private void addParameter(String name, String[] values) {
		this.parameters.put(name, values);
	}

	/**
	 * Determines if the current request matches the <code>DefaultSavedRequest</code>.
	 * <p>
	 * All URL arguments are considered but not cookies, locales, headers or parameters.
	 * @param request the actual request to be matched against this one
	 * @param portResolver used to obtain the server port of the request
	 * @return true if the request is deemed to match this one.
	 */
	public boolean doesRequestMatch(HttpServletRequest request, PortResolver portResolver) {
		if (!propertyEquals(this.pathInfo, request.getPathInfo())) {
			return false;
		}
		if (!propertyEquals(createQueryString(this.queryString, this.matchingRequestParameterName),
				request.getQueryString())) {
			return false;
		}
		if (!propertyEquals(this.requestURI, request.getRequestURI())) {
			return false;
		}
		if (!"GET".equals(request.getMethod()) && "GET".equals(this.method)) {
			// A save GET should not match an incoming non-GET method
			return false;
		}
		if (!propertyEquals(this.serverPort, portResolver.getServerPort(request))) {
			return false;
		}
		if (!propertyEquals(this.requestURL, request.getRequestURL().toString())) {
			return false;
		}
		if (!propertyEquals(this.scheme, request.getScheme())) {
			return false;
		}
		if (!propertyEquals(this.serverName, request.getServerName())) {
			return false;
		}
		if (!propertyEquals(this.contextPath, request.getContextPath())) {
			return false;
		}
		return propertyEquals(this.servletPath, request.getServletPath());

	}

	public String getContextPath() {
		return this.contextPath;
	}

	@Override
	public List<Cookie> getCookies() {
		List<Cookie> cookieList = new ArrayList<>(this.cookies.size());
		for (SavedCookie savedCookie : this.cookies) {
			cookieList.add(savedCookie.getCookie());
		}
		return cookieList;
	}

	/**
	 * Indicates the URL that the user agent used for this request.
	 * @return the full URL of this request
	 */
	@Override
	public String getRedirectUrl() {
		String queryString = createQueryString(this.queryString, this.matchingRequestParameterName);
		return UrlUtils.buildFullRequestUrl(this.scheme, this.serverName, this.serverPort, this.requestURI,
				queryString);
	}

	@Override
	public Collection<String> getHeaderNames() {
		return this.headers.keySet();
	}

	@Override
	public List<String> getHeaderValues(String name) {
		List<String> values = this.headers.get(name);
		return (values != null) ? values : Collections.emptyList();
	}

	@Override
	public List<Locale> getLocales() {
		return this.locales;
	}

	@Override
	public String getMethod() {
		return this.method;
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		return this.parameters;
	}

	public Collection<String> getParameterNames() {
		return this.parameters.keySet();
	}

	@Override
	public String[] getParameterValues(String name) {
		return this.parameters.get(name);
	}

	public String getPathInfo() {
		return this.pathInfo;
	}

	public String getQueryString() {
		return (this.queryString);
	}

	public String getRequestURI() {
		return (this.requestURI);
	}

	public String getRequestURL() {
		return this.requestURL;
	}

	public String getScheme() {
		return this.scheme;
	}

	public String getServerName() {
		return this.serverName;
	}

	public int getServerPort() {
		return this.serverPort;
	}

	public String getServletPath() {
		return this.servletPath;
	}

	private boolean propertyEquals(Object arg1, Object arg2) {
		if ((arg1 == null) && (arg2 == null)) {
			return true;
		}
		if (arg1 == null || arg2 == null) {
			return false;
		}
		return arg1.equals(arg2);
	}

	@Override
	public String toString() {
		return "DefaultSavedRequest [" + getRedirectUrl() + "]";
	}

	private static String createQueryString(String queryString, String matchingRequestParameterName) {
		if (matchingRequestParameterName == null) {
			return queryString;
		}
		if (queryString == null || queryString.length() == 0) {
			return matchingRequestParameterName;
		}
		return UriComponentsBuilder.newInstance()
			.query(queryString)
			.replaceQueryParam(matchingRequestParameterName)
			.queryParam(matchingRequestParameterName)
			.build()
			.getQuery();
	}

	/**
	 * @since 4.2
	 */
	@JsonIgnoreProperties(ignoreUnknown = true)
	@JsonPOJOBuilder(withPrefix = "set")
	public static class Builder {

		private List<SavedCookie> cookies = null;

		private List<Locale> locales = null;

		private Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

		private Map<String, String[]> parameters = new TreeMap<>();

		private String contextPath;

		private String method;

		private String pathInfo;

		private String queryString;

		private String requestURI;

		private String requestURL;

		private String scheme;

		private String serverName;

		private String servletPath;

		private int serverPort = 80;

		private String matchingRequestParameterName;

		public Builder setCookies(List<SavedCookie> cookies) {
			this.cookies = cookies;
			return this;
		}

		public Builder setLocales(List<Locale> locales) {
			this.locales = locales;
			return this;
		}

		public Builder setHeaders(Map<String, List<String>> header) {
			this.headers.putAll(header);
			return this;
		}

		public Builder setParameters(Map<String, String[]> parameters) {
			this.parameters = parameters;
			return this;
		}

		public Builder setContextPath(String contextPath) {
			this.contextPath = contextPath;
			return this;
		}

		public Builder setMethod(String method) {
			this.method = method;
			return this;
		}

		public Builder setPathInfo(String pathInfo) {
			this.pathInfo = pathInfo;
			return this;
		}

		public Builder setQueryString(String queryString) {
			this.queryString = queryString;
			return this;
		}

		public Builder setRequestURI(String requestURI) {
			this.requestURI = requestURI;
			return this;
		}

		public Builder setRequestURL(String requestURL) {
			this.requestURL = requestURL;
			return this;
		}

		public Builder setScheme(String scheme) {
			this.scheme = scheme;
			return this;
		}

		public Builder setServerName(String serverName) {
			this.serverName = serverName;
			return this;
		}

		public Builder setServletPath(String servletPath) {
			this.servletPath = servletPath;
			return this;
		}

		public Builder setServerPort(int serverPort) {
			this.serverPort = serverPort;
			return this;
		}

		public Builder setMatchingRequestParameterName(String matchingRequestParameterName) {
			this.matchingRequestParameterName = matchingRequestParameterName;
			return this;
		}

		public DefaultSavedRequest build() {
			DefaultSavedRequest savedRequest = new DefaultSavedRequest(this);
			if (!ObjectUtils.isEmpty(this.cookies)) {
				for (SavedCookie cookie : this.cookies) {
					savedRequest.addCookie(cookie.getCookie());
				}
			}
			if (!ObjectUtils.isEmpty(this.locales)) {
				savedRequest.locales.addAll(this.locales);
			}
			savedRequest.addParameters(this.parameters);
			this.headers.remove(HEADER_IF_MODIFIED_SINCE);
			this.headers.remove(HEADER_IF_NONE_MATCH);
			for (Map.Entry<String, List<String>> entry : this.headers.entrySet()) {
				String headerName = entry.getKey();
				List<String> headerValues = entry.getValue();
				for (String headerValue : headerValues) {
					savedRequest.addHeader(headerName, headerValue);
				}
			}
			return savedRequest;
		}

	}

}

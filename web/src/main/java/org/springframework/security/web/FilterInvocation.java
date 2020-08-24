/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

/**
 * Holds objects associated with a HTTP filter.
 * <P>
 * Guarantees the request and response are instances of <code>HttpServletRequest</code>
 * and <code>HttpServletResponse</code>, and that there are no <code>null</code> objects.
 * <p>
 * Required so that security system classes can obtain access to the filter environment,
 * as well as the request and response.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @author Luke Taylor
 * @author Rob Winch
 */
public class FilterInvocation {

	static final FilterChain DUMMY_CHAIN = (req, res) -> {
		throw new UnsupportedOperationException("Dummy filter chain");
	};

	private FilterChain chain;

	private HttpServletRequest request;

	private HttpServletResponse response;

	public FilterInvocation(ServletRequest request, ServletResponse response, FilterChain chain) {
		Assert.isTrue(request != null && response != null && chain != null, "Cannot pass null values to constructor");
		this.request = (HttpServletRequest) request;
		this.response = (HttpServletResponse) response;
		this.chain = chain;
	}

	public FilterInvocation(String servletPath, String method) {
		this(null, servletPath, method);
	}

	public FilterInvocation(String contextPath, String servletPath, String method) {
		this(contextPath, servletPath, null, null, method);
	}

	public FilterInvocation(String contextPath, String servletPath, String pathInfo, String query, String method) {
		DummyRequest request = new DummyRequest();
		contextPath = (contextPath != null) ? contextPath : "/cp";
		request.setContextPath(contextPath);
		request.setServletPath(servletPath);
		request.setRequestURI(contextPath + servletPath + ((pathInfo != null) ? pathInfo : ""));
		request.setPathInfo(pathInfo);
		request.setQueryString(query);
		request.setMethod(method);
		this.request = request;
	}

	public FilterChain getChain() {
		return this.chain;
	}

	/**
	 * Indicates the URL that the user agent used for this request.
	 * <p>
	 * The returned URL does <b>not</b> reflect the port number determined from a
	 * {@link org.springframework.security.web.PortResolver}.
	 * @return the full URL of this request
	 */
	public String getFullRequestUrl() {
		return UrlUtils.buildFullRequestUrl(this.request);
	}

	public HttpServletRequest getHttpRequest() {
		return this.request;
	}

	public HttpServletResponse getHttpResponse() {
		return this.response;
	}

	/**
	 * Obtains the web application-specific fragment of the URL.
	 * @return the URL, excluding any server name, context path or servlet path
	 */
	public String getRequestUrl() {
		return UrlUtils.buildRequestUrl(this.request);
	}

	public HttpServletRequest getRequest() {
		return getHttpRequest();
	}

	public HttpServletResponse getResponse() {
		return getHttpResponse();
	}

	@Override
	public String toString() {
		return "FilterInvocation: URL: " + getRequestUrl();
	}

	static class DummyRequest extends HttpServletRequestWrapper {

		private static final HttpServletRequest UNSUPPORTED_REQUEST = (HttpServletRequest) Proxy.newProxyInstance(
				DummyRequest.class.getClassLoader(), new Class[] { HttpServletRequest.class },
				new UnsupportedOperationExceptionInvocationHandler());

		private String requestURI;

		private String contextPath = "";

		private String servletPath;

		private String pathInfo;

		private String queryString;

		private String method;

		private final HttpHeaders headers = new HttpHeaders();

		private final Map<String, String[]> parameters = new LinkedHashMap<>();

		DummyRequest() {
			super(UNSUPPORTED_REQUEST);
		}

		@Override
		public String getCharacterEncoding() {
			return "UTF-8";
		}

		@Override
		public Object getAttribute(String attributeName) {
			return null;
		}

		void setRequestURI(String requestURI) {
			this.requestURI = requestURI;
		}

		void setPathInfo(String pathInfo) {
			this.pathInfo = pathInfo;
		}

		@Override
		public String getRequestURI() {
			return this.requestURI;
		}

		void setContextPath(String contextPath) {
			this.contextPath = contextPath;
		}

		@Override
		public String getContextPath() {
			return this.contextPath;
		}

		void setServletPath(String servletPath) {
			this.servletPath = servletPath;
		}

		@Override
		public String getServletPath() {
			return this.servletPath;
		}

		void setMethod(String method) {
			this.method = method;
		}

		@Override
		public String getMethod() {
			return this.method;
		}

		@Override
		public String getPathInfo() {
			return this.pathInfo;
		}

		@Override
		public String getQueryString() {
			return this.queryString;
		}

		void setQueryString(String queryString) {
			this.queryString = queryString;
		}

		@Override
		public String getServerName() {
			return null;
		}

		@Override
		public String getHeader(String name) {
			return this.headers.getFirst(name);
		}

		@Override
		public Enumeration<String> getHeaders(String name) {
			return Collections.enumeration(this.headers.get(name));
		}

		@Override
		public Enumeration<String> getHeaderNames() {
			return Collections.enumeration(this.headers.keySet());
		}

		@Override
		public int getIntHeader(String name) {
			String value = this.headers.getFirst(name);
			if (value == null) {
				return -1;
			}
			return Integer.parseInt(value);
		}

		void addHeader(String name, String value) {
			this.headers.add(name, value);
		}

		@Override
		public String getParameter(String name) {
			String[] array = this.parameters.get(name);
			return (array != null && array.length > 0) ? array[0] : null;
		}

		@Override
		public Map<String, String[]> getParameterMap() {
			return Collections.unmodifiableMap(this.parameters);
		}

		@Override
		public Enumeration<String> getParameterNames() {
			return Collections.enumeration(this.parameters.keySet());
		}

		@Override
		public String[] getParameterValues(String name) {
			return this.parameters.get(name);
		}

		void setParameter(String name, String... values) {
			this.parameters.put(name, values);
		}

	}

	static final class UnsupportedOperationExceptionInvocationHandler implements InvocationHandler {

		private static final float JAVA_VERSION = Float.parseFloat(System.getProperty("java.class.version", "52"));

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			if (method.isDefault()) {
				return invokeDefaultMethod(proxy, method, args);
			}
			throw new UnsupportedOperationException(method + " is not supported");
		}

		private Object invokeDefaultMethod(Object proxy, Method method, Object[] args) throws Throwable {
			if (isJdk8OrEarlier()) {
				return invokeDefaultMethodForJdk8(proxy, method, args);
			}
			return MethodHandles.lookup()
					.findSpecial(method.getDeclaringClass(), method.getName(),
							MethodType.methodType(method.getReturnType(), new Class[0]), method.getDeclaringClass())
					.bindTo(proxy).invokeWithArguments(args);
		}

		private Object invokeDefaultMethodForJdk8(Object proxy, Method method, Object[] args) throws Throwable {
			Constructor<Lookup> constructor = Lookup.class.getDeclaredConstructor(Class.class);
			constructor.setAccessible(true);
			Class<?> clazz = method.getDeclaringClass();
			return constructor.newInstance(clazz).in(clazz).unreflectSpecial(method, clazz).bindTo(proxy)
					.invokeWithArguments(args);
		}

		private boolean isJdk8OrEarlier() {
			return JAVA_VERSION <= 52;
		}

	}

}

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

package org.springframework.security.web.savedrequest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.http.Cookie;

import org.springframework.util.Assert;

/**
 * A Bean implementation of SavedRequest
 *
 * @author Rob Winch
 * @since 5.1
 */
public class SimpleSavedRequest implements SavedRequest {

	private String redirectUrl;

	private List<Cookie> cookies = new ArrayList<>();

	private String method = "GET";

	private Map<String, List<String>> headers = new HashMap<>();

	private List<Locale> locales = new ArrayList<>();

	private Map<String, String[]> parameters = new HashMap<>();

	public SimpleSavedRequest() {
	}

	public SimpleSavedRequest(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	public SimpleSavedRequest(SavedRequest request) {
		this.redirectUrl = request.getRedirectUrl();
		this.cookies = request.getCookies();
		for (String headerName : request.getHeaderNames()) {
			this.headers.put(headerName, request.getHeaderValues(headerName));
		}
		this.locales = request.getLocales();
		this.parameters = request.getParameterMap();
		this.method = request.getMethod();
	}

	@Override
	public String getRedirectUrl() {
		return this.redirectUrl;
	}

	@Override
	public List<Cookie> getCookies() {
		return this.cookies;
	}

	@Override
	public String getMethod() {
		return this.method;
	}

	@Override
	public List<String> getHeaderValues(String name) {
		return this.headers.getOrDefault(name, new ArrayList<>());
	}

	@Override
	public Collection<String> getHeaderNames() {
		return this.headers.keySet();
	}

	@Override
	public List<Locale> getLocales() {
		return this.locales;
	}

	@Override
	public String[] getParameterValues(String name) {
		return this.parameters.getOrDefault(name, new String[0]);
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		return this.parameters;
	}

	public void setRedirectUrl(String redirectUrl) {
		Assert.notNull(redirectUrl, "redirectUrl cannot be null");
		this.redirectUrl = redirectUrl;
	}

	public void setCookies(List<Cookie> cookies) {
		Assert.notNull(cookies, "cookies cannot be null");
		this.cookies = cookies;
	}

	public void setMethod(String method) {
		Assert.notNull(method, "method cannot be null");
		this.method = method;
	}

	public void setHeaders(Map<String, List<String>> headers) {
		Assert.notNull(headers, "headers cannot be null");
		this.headers = headers;
	}

	public void setLocales(List<Locale> locales) {
		Assert.notNull("locales cannot be null");
		this.locales = locales;
	}

	public void setParameters(Map<String, String[]> parameters) {
		Assert.notNull(parameters, "parameters cannot be null");
		this.parameters = parameters;
	}

}

/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.servlet;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.MultipartConfigElement;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.ServletSecurityElement;

import org.springframework.lang.NonNull;
import org.springframework.web.servlet.DispatcherServlet;

public class MockServletContext extends org.springframework.mock.web.MockServletContext {

	private final Map<String, ServletRegistration> registrations = new LinkedHashMap<>();

	public static MockServletContext mvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		return servletContext;
	}

	@NonNull
	@Override
	public ServletRegistration.Dynamic addServlet(@NonNull String servletName, Class<? extends Servlet> clazz) {
		ServletRegistration.Dynamic dynamic = new MockServletRegistration(servletName, clazz);
		this.registrations.put(servletName, dynamic);
		return dynamic;
	}

	@NonNull
	@Override
	public Map<String, ? extends ServletRegistration> getServletRegistrations() {
		return this.registrations;
	}

	@Override
	public ServletRegistration getServletRegistration(String servletName) {
		return this.registrations.get(servletName);
	}

	private static class MockServletRegistration implements ServletRegistration.Dynamic {

		private final String name;

		private final Class<?> clazz;

		private final Set<String> mappings = new LinkedHashSet<>();

		MockServletRegistration(String name, Class<?> clazz) {
			this.name = name;
			this.clazz = clazz;
		}

		@Override
		public void setLoadOnStartup(int loadOnStartup) {

		}

		@Override
		public Set<String> setServletSecurity(ServletSecurityElement constraint) {
			return null;
		}

		@Override
		public void setMultipartConfig(MultipartConfigElement multipartConfig) {

		}

		@Override
		public void setRunAsRole(String roleName) {

		}

		@Override
		public void setAsyncSupported(boolean isAsyncSupported) {

		}

		@Override
		public Set<String> addMapping(String... urlPatterns) {
			this.mappings.addAll(Arrays.asList(urlPatterns));
			return this.mappings;
		}

		@Override
		public Collection<String> getMappings() {
			return this.mappings;
		}

		@Override
		public String getRunAsRole() {
			return null;
		}

		@Override
		public String getName() {
			return this.name;
		}

		@Override
		public String getClassName() {
			return this.clazz.getName();
		}

		@Override
		public boolean setInitParameter(String name, String value) {
			return false;
		}

		@Override
		public String getInitParameter(String name) {
			return null;
		}

		@Override
		public Set<String> setInitParameters(Map<String, String> initParameters) {
			return null;
		}

		@Override
		public Map<String, String> getInitParameters() {
			return null;
		}

	}

}

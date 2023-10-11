/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

final class DispatcherServletDelegatingRequestMatcherBuilder implements RequestMatcherBuilder {

	final MvcRequestMatcherBuilder mvc;

	final AntPathRequestMatcherBuilder ant;

	final ServletRegistrationCollection registrations;

	DispatcherServletDelegatingRequestMatcherBuilder(MvcRequestMatcherBuilder mvc, AntPathRequestMatcherBuilder ant,
			ServletRegistrationCollection registrations) {
		this.mvc = mvc;
		this.ant = ant;
		this.registrations = registrations;
	}

	@Override
	public RequestMatcher matcher(String pattern) {
		MvcRequestMatcher mvc = this.mvc.matcher(pattern);
		AntPathRequestMatcher ant = this.ant.matcher(pattern);
		return new DispatcherServletDelegatingRequestMatcher(mvc, ant, this.registrations);
	}

	@Override
	public RequestMatcher matcher(HttpMethod method, String pattern) {
		MvcRequestMatcher mvc = this.mvc.matcher(method, pattern);
		AntPathRequestMatcher ant = this.ant.matcher(method, pattern);
		return new DispatcherServletDelegatingRequestMatcher(mvc, ant, this.registrations);
	}

	static final class DispatcherServletDelegatingRequestMatcher implements RequestMatcher {

		private final MvcRequestMatcher mvc;

		private final AntPathRequestMatcher ant;

		private final ServletRegistrationCollection registrations;

		private DispatcherServletDelegatingRequestMatcher(MvcRequestMatcher mvc, AntPathRequestMatcher ant,
				ServletRegistrationCollection registrations) {
			this.mvc = mvc;
			this.ant = ant;
			this.registrations = registrations;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistrationCollection.Registration registration = this.registrations.registrationByName(name);
			Assert.notNull(registration,
					String.format("Could not find %s in servlet configuration %s", name, this.registrations));
			if (registration.isDispatcherServlet()) {
				return this.mvc.matches(request);
			}
			return this.ant.matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistrationCollection.Registration registration = this.registrations.registrationByName(name);
			Assert.notNull(registration,
					String.format("Could not find %s in servlet configuration %s", name, this.registrations));
			if (registration.isDispatcherServlet()) {
				return this.mvc.matcher(request);
			}
			return this.ant.matcher(request);
		}

		@Override
		public String toString() {
			return String.format("DispatcherServlet [mvc=[%s], ant=[%s], servlet=[%s]]", this.mvc, this.ant,
					this.registrations);
		}

	}

}

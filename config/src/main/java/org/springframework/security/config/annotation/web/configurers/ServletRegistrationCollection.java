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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;

import org.springframework.context.ApplicationContext;
import org.springframework.util.ClassUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.WebApplicationContext;

final class ServletRegistrationCollection {

	private List<Registration> registrations;

	private ServletRegistrationCollection() {
		this.registrations = Collections.emptyList();
	}

	private ServletRegistrationCollection(List<Registration> registrations) {
		this.registrations = registrations;
	}

	static ServletRegistrationCollection registrations(ApplicationContext context) {
		if (!(context instanceof WebApplicationContext web)) {
			return new ServletRegistrationCollection();
		}
		ServletContext servletContext = web.getServletContext();
		if (servletContext == null) {
			return new ServletRegistrationCollection();
		}
		Map<String, ? extends ServletRegistration> registrations = servletContext.getServletRegistrations();
		if (registrations == null) {
			return new ServletRegistrationCollection();
		}
		List<Registration> filtered = new ArrayList<>();
		for (ServletRegistration registration : registrations.values()) {
			Collection<String> mappings = registration.getMappings();
			if (!CollectionUtils.isEmpty(mappings)) {
				filtered.add(new Registration(registration));
			}
		}
		return new ServletRegistrationCollection(filtered);
	}

	boolean isEmpty() {
		return this.registrations.isEmpty();
	}

	Registration registrationByName(String name) {
		for (Registration registration : this.registrations) {
			if (registration.registration().getName().equals(name)) {
				return registration;
			}
		}
		return null;
	}

	Registration registrationByMapping(String target) {
		for (Registration registration : this.registrations) {
			for (String mapping : registration.registration().getMappings()) {
				if (target.equals(mapping)) {
					return registration;
				}
			}
		}
		return null;
	}

	ServletRegistrationCollection dispatcherServlets() {
		List<Registration> dispatcherServlets = new ArrayList<>();
		for (Registration registration : this.registrations) {
			if (registration.isDispatcherServlet()) {
				dispatcherServlets.add(registration);
			}
		}
		return new ServletRegistrationCollection(dispatcherServlets);
	}

	ServletPath deduceOneServletPath() {
		if (this.registrations.size() > 1) {
			return null;
		}
		ServletRegistration registration = this.registrations.iterator().next().registration();
		if (registration.getMappings().size() > 1) {
			return null;
		}
		String mapping = registration.getMappings().iterator().next();
		if ("/".equals(mapping)) {
			return new ServletPath();
		}
		if (mapping.endsWith("/*")) {
			return new ServletPath(mapping.substring(0, mapping.length() - 2));
		}
		return null;
	}

	@Override
	public String toString() {
		Map<String, Collection<String>> mappings = new LinkedHashMap<>();
		for (Registration registration : this.registrations) {
			mappings.put(registration.registration().getClassName(), registration.registration().getMappings());
		}
		return mappings.toString();
	}

	record Registration(ServletRegistration registration) {
		boolean isDispatcherServlet() {
			Class<?> dispatcherServlet = ClassUtils
				.resolveClassName("org.springframework.web.servlet.DispatcherServlet", null);
			try {
				Class<?> clazz = Class.forName(this.registration.getClassName());
				if (dispatcherServlet.isAssignableFrom(clazz)) {
					return true;
				}
			}
			catch (ClassNotFoundException ex) {
				return false;
			}
			return false;
		}
	}

	record ServletPath(String path) {
		ServletPath() {
			this(null);
		}
	}

}

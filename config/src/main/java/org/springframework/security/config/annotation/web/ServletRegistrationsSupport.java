/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;

import org.springframework.util.ClassUtils;

class ServletRegistrationsSupport {

	private final Collection<RegistrationMapping> registrations;

	ServletRegistrationsSupport(ServletContext servletContext) {
		Map<String, ? extends ServletRegistration> registrations = servletContext.getServletRegistrations();
		Collection<RegistrationMapping> mappings = new ArrayList<>();
		for (Map.Entry<String, ? extends ServletRegistration> entry : registrations.entrySet()) {
			if (!entry.getValue().getMappings().isEmpty()) {
				for (String mapping : entry.getValue().getMappings()) {
					mappings.add(new RegistrationMapping(entry.getValue(), mapping));
				}
			}
		}
		this.registrations = mappings;
	}

	Collection<RegistrationMapping> dispatcherServletMappings() {
		Collection<RegistrationMapping> mappings = new ArrayList<>();
		for (RegistrationMapping registration : this.registrations) {
			if (registration.isDispatcherServlet()) {
				mappings.add(registration);
			}
		}
		return mappings;
	}

	Collection<RegistrationMapping> mappings() {
		return this.registrations;
	}

	record RegistrationMapping(ServletRegistration registration, String mapping) {
		boolean isDispatcherServlet() {
			Class<?> dispatcherServlet = ClassUtils
				.resolveClassName("org.springframework.web.servlet.DispatcherServlet", null);
			try {
				Class<?> clazz = Class.forName(this.registration.getClassName());
				return dispatcherServlet.isAssignableFrom(clazz);
			}
			catch (ClassNotFoundException ex) {
				return false;
			}
		}

		boolean isDefault() {
			return "/".equals(this.mapping);
		}
	}

}

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

package org.springframework.security.config.annotation.web.builders;

import java.util.List;

import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.test.util.ReflectionTestUtils;

public final class TestHttpSecurities {

	private TestHttpSecurities() {

	}

	public static void disableDefaults(HttpSecurity http) throws Exception {
		List<Object> orderedFilters = (List<Object>) ReflectionTestUtils.getField(http, "filters");
		orderedFilters.clear();
		http.csrf((c) -> c.disable())
			.exceptionHandling((c) -> c.disable())
			.headers((c) -> c.disable())
			.sessionManagement((c) -> c.disable())
			.securityContext((c) -> c.disable())
			.requestCache((c) -> c.disable())
			.anonymous((c) -> c.disable())
			.servletApi((c) -> c.disable())
			.removeConfigurer(DefaultLoginPageConfigurer.class);
		http.logout((c) -> c.disable());
	}

}

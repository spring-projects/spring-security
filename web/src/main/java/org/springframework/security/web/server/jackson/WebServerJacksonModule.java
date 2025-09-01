/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.server.jackson;

import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;

/**
 * Jackson module for spring-security-web-flux. This module register
 * {@link DefaultCsrfServerTokenMixin}.
 *
 * <p>
 * The recommended way to configure it is to use {@link SecurityJacksonModules} in order
 * to enable properly automatic inclusion of type information with related validation.
 *
 * <pre>
 *     ClassLoader loader = getClass().getClassLoader();
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModules(SecurityJacksonModules.getModules(loader))
 * 				.build();
 * </pre>
 *
 * @author Boris Finkelshteyn
 * @since 5.1
 * @see SecurityJacksonModules
 */
@SuppressWarnings("serial")
public class WebServerJacksonModule extends SecurityJacksonModule {

	private static final String NAME = WebServerJacksonModule.class.getName();

	private static final Version VERSION = new Version(1, 0, 0, null, null, null);

	public WebServerJacksonModule() {
		super(NAME, VERSION);
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(DefaultCsrfToken.class, DefaultCsrfServerTokenMixin.class);
	}

}

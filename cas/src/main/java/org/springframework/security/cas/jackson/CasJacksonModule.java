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

package org.springframework.security.cas.jackson;

import org.apereo.cas.client.authentication.AttributePrincipalImpl;
import org.apereo.cas.client.validation.AssertionImpl;
import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;

/**
 * Jackson module for spring-security-cas. This module register
 * {@link AssertionImplMixin}, {@link AttributePrincipalImplMixin} and
 * {@link CasAuthenticationTokenMixin}. If no default typing enabled by default then it'll
 * enable it because typing info is needed to properly serialize/deserialize objects. In
 * order to use this module just add this module into your JsonMapper configuration.
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
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see SecurityJacksonModules
 */
public class CasJacksonModule extends SecurityJacksonModule {

	public CasJacksonModule() {
		super(CasJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(AssertionImpl.class)
			.allowIfSubType(AttributePrincipalImpl.class)
			.allowIfSubType(CasAuthenticationToken.class);
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(AssertionImpl.class, AssertionImplMixin.class);
		context.setMixIn(AttributePrincipalImpl.class, AttributePrincipalImplMixin.class);
		context.setMixIn(CasAuthenticationToken.class, CasAuthenticationTokenMixin.class);
	}

}

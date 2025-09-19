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
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.module.SimpleModule;

import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.jackson.AllowlistTypeResolverBuilder;
import org.springframework.security.jackson.SecurityJacksonModules;

/**
 * Jackson module for spring-security-cas. This module register
 * {@link AssertionImplMixin}, {@link AttributePrincipalImplMixin} and
 * {@link CasAuthenticationTokenMixin}. If no default typing enabled by default then it'll
 * enable it because typing info is needed to properly serialize/deserialize objects. In
 * order to use this module just add this module into your JsonMapper configuration.
 *
 * <pre>
 * JsonMapper mapper = JsonMapper.builder()
 * 				.addModule(new CasJacksonModule())
 * 				.build();
 * </pre>
 *
 * <b>Note: use {@link SecurityJacksonModules#getModules(ClassLoader)} to get list of all
 * security modules on the classpath.</b>
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see SecurityJacksonModules
 */
public class CasJacksonModule extends SimpleModule {

	public CasJacksonModule() {
		super(CasJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		((MapperBuilder<?, ?>) context.getOwner()).setDefaultTyping(new AllowlistTypeResolverBuilder());
		context.setMixIn(AssertionImpl.class, AssertionImplMixin.class);
		context.setMixIn(AttributePrincipalImpl.class, AttributePrincipalImplMixin.class);
		context.setMixIn(CasAuthenticationToken.class, CasAuthenticationTokenMixin.class);
	}

}

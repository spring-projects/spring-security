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

package org.springframework.security.jackson;

import tools.jackson.core.Version;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.module.SimpleModule;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Jackson module for spring-security-core. This module register
 * {@link AnonymousAuthenticationTokenMixin}, {@link RememberMeAuthenticationTokenMixin},
 * {@link SimpleGrantedAuthorityMixin}, {{@link UserMixin},
 * {@link UsernamePasswordAuthenticationTokenMixin} and
 * {@link UsernamePasswordAuthenticationTokenMixin}. If no default typing enabled by
 * default then it'll enable it because typing info is needed to properly
 * serialize/deserialize objects. In order to use this module just add this module into
 * your JsonMapper configuration.
 *
 * <pre>
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModule(new CoreJacksonModule())
 * 				.build();
 * </pre>
 *
 * <b>Note: use {@link SecurityJacksonModules#getModules(ClassLoader)} to get list of all
 * security modules.</b>
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.O
 * @see SecurityJacksonModules
 */
@SuppressWarnings("serial")
public class CoreJacksonModule extends SimpleModule {

	public CoreJacksonModule() {
		super(CoreJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		((MapperBuilder<?, ?>) context.getOwner()).setDefaultTyping(new AllowlistTypeResolverBuilder());
		context.setMixIn(AnonymousAuthenticationToken.class, AnonymousAuthenticationTokenMixin.class);
		context.setMixIn(RememberMeAuthenticationToken.class, RememberMeAuthenticationTokenMixin.class);
		context.setMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);
		context.setMixIn(FactorGrantedAuthority.class, FactorGrantedAuthorityMixin.class);
		context.setMixIn(User.class, UserMixin.class);
		context.setMixIn(UsernamePasswordAuthenticationToken.class, UsernamePasswordAuthenticationTokenMixin.class);
		context.setMixIn(BadCredentialsException.class, BadCredentialsExceptionMixin.class);
	}

}

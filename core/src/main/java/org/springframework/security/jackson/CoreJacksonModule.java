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

import java.time.Duration;
import java.time.Instant;

import tools.jackson.core.Version;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;

/**
 * Jackson module for spring-security-core. This module register
 * {@link AnonymousAuthenticationTokenMixin}, {@link RememberMeAuthenticationTokenMixin},
 * {@link SimpleGrantedAuthorityMixin}, {@link FactorGrantedAuthorityMixin},
 * {{@link UserMixin}, {@link UsernamePasswordAuthenticationTokenMixin} and
 * {@link UsernamePasswordAuthenticationTokenMixin}.
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
 * @since 7.O
 * @see SecurityJacksonModules
 */
@SuppressWarnings("serial")
public class CoreJacksonModule extends SecurityJacksonModule {

	public CoreJacksonModule() {
		super(CoreJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	protected CoreJacksonModule(String name, Version version) {
		super(name, version);
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(Instant.class)
			.allowIfSubType(Duration.class)
			.allowIfSubType(SimpleGrantedAuthority.class)
			.allowIfSubType(FactorGrantedAuthority.class)
			.allowIfSubType(UsernamePasswordAuthenticationToken.class)
			.allowIfSubType(RememberMeAuthenticationToken.class)
			.allowIfSubType(AnonymousAuthenticationToken.class)
			.allowIfSubType(User.class)
			.allowIfSubType(BadCredentialsException.class)
			.allowIfSubType(SecurityContextImpl.class)
			.allowIfSubType(TestingAuthenticationToken.class)
			.allowIfSubType(OneTimeTokenAuthentication.class)
			.allowIfSubType("java.util.Collections$UnmodifiableSet")
			.allowIfSubType("java.util.Collections$UnmodifiableRandomAccessList")
			.allowIfSubType("java.util.Collections$EmptyList")
			.allowIfSubType("java.util.ArrayList")
			.allowIfSubType("java.util.HashMap")
			.allowIfSubType("java.util.Collections$EmptyMap")
			.allowIfSubType("java.util.Date")
			.allowIfSubType("java.util.Arrays$ArrayList")
			.allowIfSubType("java.util.Collections$UnmodifiableMap")
			.allowIfSubType("java.util.LinkedHashMap")
			.allowIfSubType("java.util.Collections$SingletonList")
			.allowIfSubType("java.util.TreeMap")
			.allowIfSubType("java.util.HashSet")
			.allowIfSubType("java.util.LinkedHashSet");
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(AnonymousAuthenticationToken.class, AnonymousAuthenticationTokenMixin.class);
		context.setMixIn(RememberMeAuthenticationToken.class, RememberMeAuthenticationTokenMixin.class);
		context.setMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);
		context.setMixIn(FactorGrantedAuthority.class, FactorGrantedAuthorityMixin.class);
		context.setMixIn(User.class, UserMixin.class);
		context.setMixIn(UsernamePasswordAuthenticationToken.class, UsernamePasswordAuthenticationTokenMixin.class);
		context.setMixIn(TestingAuthenticationToken.class, TestingAuthenticationTokenMixin.class);
		context.setMixIn(BadCredentialsException.class, BadCredentialsExceptionMixin.class);
		context.setMixIn(OneTimeTokenAuthentication.class, OneTimeTokenAuthenticationMixin.class);
	}

}

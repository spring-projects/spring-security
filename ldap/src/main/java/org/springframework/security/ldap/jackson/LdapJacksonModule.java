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

package org.springframework.security.ldap.jackson;

import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.LdapAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.ldap.userdetails.Person;

/**
 * Jackson module for {@code spring-security-ldap}. This module registers
 * {@link LdapAuthorityMixin}, {@link LdapUserDetailsImplMixin}, {@link PersonMixin},
 * {@link InetOrgPersonMixin}.
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
 * @since 7.0
 * @see SecurityJacksonModules
 */
@SuppressWarnings("serial")
public class LdapJacksonModule extends SecurityJacksonModule {

	public LdapJacksonModule() {
		super(LdapJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(InetOrgPerson.class)
			.allowIfSubType(LdapUserDetailsImpl.class)
			.allowIfSubType(Person.class);
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(LdapAuthority.class, LdapAuthorityMixin.class);
		context.setMixIn(LdapUserDetailsImpl.class, LdapUserDetailsImplMixin.class);
		context.setMixIn(Person.class, PersonMixin.class);
		context.setMixIn(InetOrgPerson.class, InetOrgPersonMixin.class);
	}

}

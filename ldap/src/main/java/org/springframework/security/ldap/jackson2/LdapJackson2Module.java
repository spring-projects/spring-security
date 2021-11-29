/*
 * Copyright 2015-2021 the original author or authors.
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

package org.springframework.security.ldap.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.LdapAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.ldap.userdetails.Person;

/**
 * Jackson module for {@code spring-security-ldap}. This module registers
 * {@link LdapAuthorityMixin}, {@link LdapUserDetailsImplMixin}, {@link PersonMixin},
 * {@link InetOrgPersonMixin}.
 *
 * If not already enabled, default typing will be automatically enabled as type info is
 * required to properly serialize/deserialize objects. In order to use this module just
 * add it to your {@code ObjectMapper} configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new LdapJackson2Module());
 * </pre>
 *
 * <b>Note: use {@link SecurityJackson2Modules#getModules(ClassLoader)} to get list of all
 * security modules.</b>
 *
 * @since 5.7
 * @see SecurityJackson2Modules
 */
public class LdapJackson2Module extends SimpleModule {

	public LdapJackson2Module() {
		super(LdapJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
		context.setMixInAnnotations(LdapAuthority.class, LdapAuthorityMixin.class);
		context.setMixInAnnotations(LdapUserDetailsImpl.class, LdapUserDetailsImplMixin.class);
		context.setMixInAnnotations(Person.class, PersonMixin.class);
		context.setMixInAnnotations(InetOrgPerson.class, InetOrgPersonMixin.class);
	}

}

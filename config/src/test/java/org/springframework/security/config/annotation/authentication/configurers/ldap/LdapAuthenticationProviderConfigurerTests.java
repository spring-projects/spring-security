/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configurers.ldap;

import org.junit.Before;
import org.junit.Test;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.NullLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.util.ReflectionTestUtils.getField;
import static org.springframework.test.util.ReflectionTestUtils.invokeMethod;

public class LdapAuthenticationProviderConfigurerTests {

	private LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> configurer;

	@Before
	public void setUp() {
		this.configurer = new LdapAuthenticationProviderConfigurer<>();
	}

	// SEC-2557
	@Test
	public void getAuthoritiesMapper() throws Exception {
		assertThat(this.configurer.getAuthoritiesMapper()).isInstanceOf(SimpleAuthorityMapper.class);
		this.configurer.authoritiesMapper(new NullAuthoritiesMapper());
		assertThat(this.configurer.getAuthoritiesMapper()).isInstanceOf(NullAuthoritiesMapper.class);
	}

	@Test
	public void customAuthoritiesPopulator() throws Exception {
		assertThat(getField(this.configurer, "ldapAuthoritiesPopulator")).isNull();
		this.configurer.ldapAuthoritiesPopulator(new NullLdapAuthoritiesPopulator());
		assertThat(getField(this.configurer, "ldapAuthoritiesPopulator")).isInstanceOf(NullLdapAuthoritiesPopulator.class);
	}

	@Test
	public void authoritiesPopulatorIsPostProcessed() throws Exception {
		assertThat(getField(this.configurer, "ldapAuthoritiesPopulator")).isNull();
		this.configurer.contextSource(new DefaultSpringSecurityContextSource("ldap://localhost:389"));
		this.configurer.addObjectPostProcessor(
				new ObjectPostProcessor<LdapAuthoritiesPopulator>() {
					@Override
					public <O extends LdapAuthoritiesPopulator> O postProcess(O object) {
						if (object instanceof DefaultLdapAuthoritiesPopulator) {
							return (O)new TestPostProcessLdapAuthoritiesPopulator();
						}
						else {
							return object;
						}
					}
				}
		);
		invokeMethod(this.configurer, "getLdapAuthoritiesPopulator");
		assertThat(getField(this.configurer, "ldapAuthoritiesPopulator"))
				.isInstanceOf(TestPostProcessLdapAuthoritiesPopulator.class);
	}

	private static class TestPostProcessLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {
		@Override
		public Collection<? extends GrantedAuthority> getGrantedAuthorities(
				DirContextOperations userData, String username) {
			return null;
		}
	}

}

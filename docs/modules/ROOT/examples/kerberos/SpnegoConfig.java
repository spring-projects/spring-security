/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kerberos.docs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

//tag::snippetA[]
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Value("${app.ad-domain}")
	private String adDomain;

	@Value("${app.ad-server}")
	private String adServer;

	@Value("${app.service-principal}")
	private String servicePrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.ldap-search-base}")
	private String ldapSearchBase;

	@Value("${app.ldap-search-filter}")
	private String ldapSearchFilter;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider = kerberosServiceAuthenticationProvider();
		ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider = activeDirectoryLdapAuthenticationProvider();
		ProviderManager providerManager = new ProviderManager(kerberosServiceAuthenticationProvider,
				activeDirectoryLdapAuthenticationProvider);

		http
			.authorizeHttpRequests((authz) -> authz
				.requestMatchers("/", "/home").permitAll()
				.anyRequest().authenticated()
			)
			.exceptionHandling()
				.authenticationEntryPoint(spnegoEntryPoint())
				.and()
			.formLogin()
				.loginPage("/login").permitAll()
				.and()
			.logout()
				.permitAll()
				.and()
			.authenticationProvider(activeDirectoryLdapAuthenticationProvider())
			.authenticationProvider(kerberosServiceAuthenticationProvider())
			.addFilterBefore(spnegoAuthenticationProcessingFilter(providerManager),
				BasicAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
		return new ActiveDirectoryLdapAuthenticationProvider(adDomain, adServer);
	}

	@Bean
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint("/login");
	}

	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager) {
		SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}

	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() throws Exception {
		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
		provider.setTicketValidator(sunJaasKerberosTicketValidator());
		provider.setUserDetailsService(ldapUserDetailsService());
		return provider;
	}

	@Bean
	public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
		SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
		ticketValidator.setServicePrincipal(servicePrincipal);
		ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
		ticketValidator.setDebug(true);
		return ticketValidator;
	}

	@Bean
	public KerberosLdapContextSource kerberosLdapContextSource() throws Exception {
		KerberosLdapContextSource contextSource = new KerberosLdapContextSource(adServer);
		contextSource.setLoginConfig(loginConfig());
		return contextSource;
	}

	public SunJaasKrb5LoginConfig loginConfig() throws Exception {
		SunJaasKrb5LoginConfig loginConfig = new SunJaasKrb5LoginConfig();
		loginConfig.setKeyTabLocation(new FileSystemResource(keytabLocation));
		loginConfig.setServicePrincipal(servicePrincipal);
		loginConfig.setDebug(true);
		loginConfig.setIsInitiator(true);
		loginConfig.afterPropertiesSet();
		return loginConfig;
	}

	@Bean
	public LdapUserDetailsService ldapUserDetailsService() throws Exception {
		FilterBasedLdapUserSearch userSearch =
				new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource());
		LdapUserDetailsService service =
				new LdapUserDetailsService(userSearch, new ActiveDirectoryLdapAuthoritiesPopulator());
		service.setUserDetailsMapper(new LdapUserDetailsMapper());
		return service;
	}
}
//end::snippetA[]

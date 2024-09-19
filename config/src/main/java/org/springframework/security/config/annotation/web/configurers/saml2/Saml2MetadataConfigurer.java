/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.saml2;

import java.util.function.Function;

import org.opensaml.core.Version;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml4MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml5MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for SAML 2.0 Metadata.
 *
 * <p>
 * SAML 2.0 Metadata provides an application with the capability to publish configuration
 * information as a {@code <md:EntityDescriptor>} or {@code <md:EntitiesDescriptor>}.
 *
 * <p>
 * Defaults are provided for all configuration options with the only required
 * configuration being a {@link Saml2LoginConfigurer#relyingPartyRegistrationRepository}.
 * Alternatively, a {@link RelyingPartyRegistrationRepository} {@code @Bean} may be
 * registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter} is populated:
 *
 * <ul>
 * <li>{@link Saml2MetadataFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * none
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link RelyingPartyRegistrationRepository} (required)</li>
 * </ul>
 *
 * @since 6.1
 * @see HttpSecurity#saml2Metadata()
 * @see Saml2MetadataFilter
 * @see RelyingPartyRegistrationRepository
 */
public class Saml2MetadataConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<Saml2LogoutConfigurer<H>, H> {

	private static final boolean USE_OPENSAML_5 = Version.getVersion().startsWith("5");

	private final ApplicationContext context;

	private Function<RelyingPartyRegistrationRepository, Saml2MetadataResponseResolver> metadataResponseResolver;

	public Saml2MetadataConfigurer(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * Use this endpoint to request relying party metadata.
	 *
	 * <p>
	 * If you specify a {@code registrationId} placeholder in the URL, then the filter
	 * will lookup a {@link RelyingPartyRegistration} using that.
	 *
	 * <p>
	 * If there is no {@code registrationId} and your
	 * {@link RelyingPartyRegistrationRepository} is {code Iterable}, the metadata
	 * endpoint will try and show all relying parties' metadata in a single
	 * {@code <md:EntitiesDecriptor} element.
	 *
	 * <p>
	 * If you need a more sophisticated lookup strategy than these, use
	 * {@link #metadataResponseResolver} instead.
	 * @param metadataUrl the url to use
	 * @return the {@link Saml2MetadataConfigurer} for more customizations
	 */
	public Saml2MetadataConfigurer<H> metadataUrl(String metadataUrl) {
		Assert.hasText(metadataUrl, "metadataUrl cannot be empty");
		this.metadataResponseResolver = (registrations) -> {
			if (USE_OPENSAML_5) {
				RequestMatcherMetadataResponseResolver metadata = new RequestMatcherMetadataResponseResolver(
						registrations, new OpenSaml5MetadataResolver());
				metadata.setRequestMatcher(new AntPathRequestMatcher(metadataUrl));
				return metadata;
			}
			RequestMatcherMetadataResponseResolver metadata = new RequestMatcherMetadataResponseResolver(registrations,
					new OpenSaml4MetadataResolver());
			metadata.setRequestMatcher(new AntPathRequestMatcher(metadataUrl));
			return metadata;
		};
		return this;
	}

	/**
	 * Use this {@link Saml2MetadataResponseResolver} to parse the request and respond
	 * with SAML 2.0 metadata.
	 * @param metadataResponseResolver to use
	 * @return the {@link Saml2MetadataConfigurer} for more customizations
	 */
	public Saml2MetadataConfigurer<H> metadataResponseResolver(Saml2MetadataResponseResolver metadataResponseResolver) {
		Assert.notNull(metadataResponseResolver, "metadataResponseResolver cannot be null");
		this.metadataResponseResolver = (registrations) -> metadataResponseResolver;
		return this;
	}

	public H and() {
		return getBuilder();
	}

	@Override
	public void configure(H http) throws Exception {
		Saml2MetadataResponseResolver metadataResponseResolver = createMetadataResponseResolver(http);
		http.addFilterBefore(new Saml2MetadataFilter(metadataResponseResolver), BasicAuthenticationFilter.class);
	}

	private Saml2MetadataResponseResolver createMetadataResponseResolver(H http) {
		if (this.metadataResponseResolver != null) {
			RelyingPartyRegistrationRepository registrations = getRelyingPartyRegistrationRepository(http);
			return this.metadataResponseResolver.apply(registrations);
		}
		Saml2MetadataResponseResolver metadataResponseResolver = getBeanOrNull(Saml2MetadataResponseResolver.class);
		if (metadataResponseResolver != null) {
			return metadataResponseResolver;
		}
		RelyingPartyRegistrationRepository registrations = getRelyingPartyRegistrationRepository(http);
		if (USE_OPENSAML_5) {
			return new RequestMatcherMetadataResponseResolver(registrations, new OpenSaml5MetadataResolver());
		}
		return new RequestMatcherMetadataResponseResolver(registrations, new OpenSaml4MetadataResolver());
	}

	private RelyingPartyRegistrationRepository getRelyingPartyRegistrationRepository(H http) {
		Saml2LoginConfigurer<H> login = http.getConfigurer(Saml2LoginConfigurer.class);
		if (login != null) {
			return login.relyingPartyRegistrationRepository(http);
		}
		else {
			return getBeanOrNull(RelyingPartyRegistrationRepository.class);
		}
	}

	private <C> C getBeanOrNull(Class<C> clazz) {
		if (this.context == null) {
			return null;
		}
		return this.context.getBeanProvider(clazz).getIfAvailable();
	}

}

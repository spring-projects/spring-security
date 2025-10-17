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

package org.springframework.security.saml2.jackson;

import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertion;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;

/**
 * Jackson module for saml2-service-provider. This module register
 * {@link Saml2AuthenticationMixin}, {@link Saml2AssertionAuthenticationMixin},
 * {@link SimpleSaml2ResponseAssertionAccessorMixin},
 * {@link DefaultSaml2AuthenticatedPrincipalMixin}, {@link Saml2LogoutRequestMixin},
 * {@link Saml2RedirectAuthenticationRequestMixin},
 * {@link Saml2PostAuthenticationRequestMixin}, {@link Saml2ErrorMixin} and
 * {@link Saml2AuthenticationExceptionMixin}.
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
public class Saml2JacksonModule extends SecurityJacksonModule {

	public Saml2JacksonModule() {
		super(Saml2JacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(Saml2ResponseAssertion.class)
			.allowIfSubType(DefaultSaml2AuthenticatedPrincipal.class)
			.allowIfSubType(Saml2PostAuthenticationRequest.class)
			.allowIfSubType(Saml2LogoutRequest.class)
			.allowIfSubType(Saml2RedirectAuthenticationRequest.class)
			.allowIfSubType(Saml2AuthenticationException.class)
			.allowIfSubType(Saml2Error.class)
			.allowIfSubType(Saml2AssertionAuthentication.class)
			.allowIfSubType(Saml2Authentication.class);
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(Saml2Authentication.class, Saml2AuthenticationMixin.class);
		context.setMixIn(Saml2AssertionAuthentication.class, Saml2AssertionAuthenticationMixin.class);
		context.setMixIn(Saml2ResponseAssertion.class, SimpleSaml2ResponseAssertionAccessorMixin.class);
		context.setMixIn(DefaultSaml2AuthenticatedPrincipal.class, DefaultSaml2AuthenticatedPrincipalMixin.class);
		context.setMixIn(Saml2LogoutRequest.class, Saml2LogoutRequestMixin.class);
		context.setMixIn(Saml2RedirectAuthenticationRequest.class, Saml2RedirectAuthenticationRequestMixin.class);
		context.setMixIn(Saml2PostAuthenticationRequest.class, Saml2PostAuthenticationRequestMixin.class);
		context.setMixIn(Saml2Error.class, Saml2ErrorMixin.class);
		context.setMixIn(Saml2AuthenticationException.class, Saml2AuthenticationExceptionMixin.class);
	}

}

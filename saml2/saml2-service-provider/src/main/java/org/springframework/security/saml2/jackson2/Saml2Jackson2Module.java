/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;

/**
 * Jackson module for saml2-service-provider. This module register
 * {@link Saml2AuthenticationMixin}, {@link DefaultSaml2AuthenticatedPrincipalMixin},
 * {@link Saml2LogoutRequestMixin}, {@link Saml2RedirectAuthenticationRequestMixin},
 * {@link Saml2PostAuthenticationRequestMixin}, {@link Saml2ErrorMixin} and
 * {@link Saml2AuthenticationExceptionMixin}.
 *
 * @author Ulrich Grave
 * @since 5.7
 * @see SecurityJackson2Modules
 */
public class Saml2Jackson2Module extends SimpleModule {

	public Saml2Jackson2Module() {
		super(Saml2Jackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(Saml2Authentication.class, Saml2AuthenticationMixin.class);
		context.setMixInAnnotations(DefaultSaml2AuthenticatedPrincipal.class,
				DefaultSaml2AuthenticatedPrincipalMixin.class);
		context.setMixInAnnotations(Saml2LogoutRequest.class, Saml2LogoutRequestMixin.class);
		context.setMixInAnnotations(Saml2RedirectAuthenticationRequest.class,
				Saml2RedirectAuthenticationRequestMixin.class);
		context.setMixInAnnotations(Saml2PostAuthenticationRequest.class, Saml2PostAuthenticationRequestMixin.class);
		context.setMixInAnnotations(Saml2Error.class, Saml2ErrorMixin.class);
		context.setMixInAnnotations(Saml2AuthenticationException.class, Saml2AuthenticationExceptionMixin.class);
	}

}

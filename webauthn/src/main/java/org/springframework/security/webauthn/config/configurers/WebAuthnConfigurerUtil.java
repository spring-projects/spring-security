/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.config.configurers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import org.springframework.security.webauthn.challenge.ChallengeRepository;
import org.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import org.springframework.security.webauthn.options.OptionsProvider;
import org.springframework.security.webauthn.options.OptionsProviderImpl;
import org.springframework.security.webauthn.server.ServerPropertyProvider;
import org.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

/**
 * Internal utility for WebAuthn Configurers
 */
public class WebAuthnConfigurerUtil {

	private WebAuthnConfigurerUtil() {
	}

	static <H extends HttpSecurityBuilder<H>> ChallengeRepository getOrCreateChallengeRepository(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		ChallengeRepository challengeRepository;
		String[] beanNames = applicationContext.getBeanNamesForType(ChallengeRepository.class);
		if (beanNames.length == 0) {
			challengeRepository = new HttpSessionChallengeRepository();
		} else {
			challengeRepository = applicationContext.getBean(ChallengeRepository.class);
		}
		return challengeRepository;
	}

	public static <H extends HttpSecurityBuilder<H>> OptionsProvider getOrCreateOptionsProvider(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		OptionsProvider optionsProvider;
		String[] beanNames = applicationContext.getBeanNamesForType(OptionsProvider.class);
		if (beanNames.length == 0) {
			WebAuthnUserDetailsService userDetailsService = getWebAuthnUserDetailsService(http);
			ChallengeRepository challengeRepository = getOrCreateChallengeRepository(http);
			optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
		} else {
			optionsProvider = applicationContext.getBean(OptionsProvider.class);
		}
		return optionsProvider;
	}


	public static <H extends HttpSecurityBuilder<H>> JsonConverter getOrCreateJsonConverter(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		JsonConverter jsonConverter;
		String[] beanNames = applicationContext.getBeanNamesForType(JsonConverter.class);
		if (beanNames.length == 0) {
			ObjectMapper jsonMapper = new ObjectMapper();
			ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
			jsonConverter = new JsonConverter(jsonMapper, cborMapper);
		} else {
			jsonConverter = applicationContext.getBean(JsonConverter.class);
		}
		return jsonConverter;
	}

	public static <H extends HttpSecurityBuilder<H>> ServerPropertyProvider getOrCreateServerPropertyProvider(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		ServerPropertyProvider serverPropertyProvider;
		String[] beanNames = applicationContext.getBeanNamesForType(ServerPropertyProvider.class);
		if (beanNames.length == 0) {
			serverPropertyProvider = new ServerPropertyProviderImpl(getOrCreateOptionsProvider(http), getOrCreateChallengeRepository(http));
		} else {
			serverPropertyProvider = applicationContext.getBean(ServerPropertyProvider.class);
		}
		return serverPropertyProvider;
	}

	public static <H extends HttpSecurityBuilder<H>> WebAuthnUserDetailsService getWebAuthnUserDetailsService(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		return applicationContext.getBean(WebAuthnUserDetailsService.class);
	}

	public static <H extends HttpSecurityBuilder<H>> WebAuthnRegistrationRequestValidator getOrCreateWebAuthnRegistrationRequestValidator(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;
		String[] beanNames = applicationContext.getBeanNamesForType(WebAuthnRegistrationRequestValidator.class);
		if (beanNames.length == 0) {
			webAuthnRegistrationRequestValidator = new WebAuthnRegistrationRequestValidator(getOrCreateWebAuthnRegistrationContextValidator(http), getOrCreateServerPropertyProvider(http));
		} else {
			webAuthnRegistrationRequestValidator = applicationContext.getBean(WebAuthnRegistrationRequestValidator.class);
		}
		return webAuthnRegistrationRequestValidator;
	}

	public static <H extends HttpSecurityBuilder<H>> WebAuthnRegistrationContextValidator getOrCreateWebAuthnRegistrationContextValidator(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator;
		String[] beanNames = applicationContext.getBeanNamesForType(WebAuthnRegistrationContextValidator.class);
		if (beanNames.length == 0) {
			webAuthnRegistrationContextValidator = WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();
		} else {
			webAuthnRegistrationContextValidator = applicationContext.getBean(WebAuthnRegistrationContextValidator.class);
		}
		return webAuthnRegistrationContextValidator;
	}
}

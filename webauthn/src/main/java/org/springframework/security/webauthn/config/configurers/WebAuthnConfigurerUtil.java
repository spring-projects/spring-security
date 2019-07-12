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
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.webauthn.WebAuthn4JWebAuthnManager;
import org.springframework.security.webauthn.WebAuthnDataConverter;
import org.springframework.security.webauthn.WebAuthnManager;
import org.springframework.security.webauthn.challenge.HttpSessionWebAuthnChallengeRepository;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeRepository;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProvider;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProviderImpl;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

/**
 * Internal utility for WebAuthn Configurers
 */
public class WebAuthnConfigurerUtil {

	private WebAuthnConfigurerUtil() {
	}

	public static <H extends HttpSecurityBuilder<H>> WebAuthnManager getOrCreateWebAuthnAuthenticationManager(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnManager webAuthnManager;
		String[] beanNames = applicationContext.getBeanNamesForType(WebAuthnManager.class);
		if (beanNames.length == 0) {
			WebAuthnDataConverter webAuthnDataConverter = getOrCreateWebAuthnDataConverter(http);
			webAuthnManager = new WebAuthn4JWebAuthnManager(
					getOrCreateWebAuthnRegistrationContextValidator(http),
					getOrCreateWebAuthnAuthenticationContextValidator(http),
					webAuthnDataConverter
			);
		} else {
			webAuthnManager = applicationContext.getBean(WebAuthnManager.class);
		}
		return webAuthnManager;
	}

	public static <H extends HttpSecurityBuilder<H>> WebAuthnServerPropertyProvider getOrCreateServerPropertyProvider(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnServerPropertyProvider webAuthnServerPropertyProvider;
		String[] beanNames = applicationContext.getBeanNamesForType(WebAuthnServerPropertyProvider.class);
		if (beanNames.length == 0) {
			webAuthnServerPropertyProvider = new WebAuthnServerPropertyProviderImpl(getOrCreateWebAuthnAuthenticationManager(http), getOrCreateChallengeRepository(http));
		} else {
			webAuthnServerPropertyProvider = applicationContext.getBean(WebAuthnServerPropertyProvider.class);
		}
		return webAuthnServerPropertyProvider;
	}

	public static <H extends HttpSecurityBuilder<H>> WebAuthnUserDetailsService getWebAuthnUserDetailsService(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		return applicationContext.getBean(WebAuthnUserDetailsService.class);
	}

	static <H extends HttpSecurityBuilder<H>> WebAuthnDataConverter getOrCreateWebAuthnDataConverter(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnDataConverter webAuthnDataConverter;
		String[] beanNames = applicationContext.getBeanNamesForType(JsonConverter.class);
		if (beanNames.length == 0) {
			ObjectMapper jsonMapper = new ObjectMapper();
			ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
			webAuthnDataConverter = new WebAuthnDataConverter(jsonMapper, cborMapper);
		} else {
			webAuthnDataConverter = applicationContext.getBean(WebAuthnDataConverter.class);
		}
		return webAuthnDataConverter;
	}

	private static <H extends HttpSecurityBuilder<H>> WebAuthnRegistrationContextValidator getOrCreateWebAuthnRegistrationContextValidator(H http) {
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

	private static <H extends HttpSecurityBuilder<H>> WebAuthnAuthenticationContextValidator getOrCreateWebAuthnAuthenticationContextValidator(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator;
		String[] beanNames = applicationContext.getBeanNamesForType(WebAuthnAuthenticationContextValidator.class);
		if (beanNames.length == 0) {
			WebAuthnDataConverter webAuthnDataConverter = getOrCreateWebAuthnDataConverter(http);
			JsonConverter jsonConverter = new JsonConverter(webAuthnDataConverter.getJsonMapper(), webAuthnDataConverter.getCborMapper());
			CborConverter cborConverter = new CborConverter(webAuthnDataConverter.getJsonMapper(), webAuthnDataConverter.getCborMapper());
			webAuthnAuthenticationContextValidator = new WebAuthnAuthenticationContextValidator(jsonConverter, cborConverter);
		} else {
			webAuthnAuthenticationContextValidator = applicationContext.getBean(WebAuthnAuthenticationContextValidator.class);
		}
		return webAuthnAuthenticationContextValidator;
	}

	private static <H extends HttpSecurityBuilder<H>> WebAuthnChallengeRepository getOrCreateChallengeRepository(H http) {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		WebAuthnChallengeRepository webAuthnChallengeRepository;
		String[] beanNames = applicationContext.getBeanNamesForType(WebAuthnChallengeRepository.class);
		if (beanNames.length == 0) {
			webAuthnChallengeRepository = new HttpSessionWebAuthnChallengeRepository();
		} else {
			webAuthnChallengeRepository = applicationContext.getBean(WebAuthnChallengeRepository.class);
		}
		return webAuthnChallengeRepository;
	}
}

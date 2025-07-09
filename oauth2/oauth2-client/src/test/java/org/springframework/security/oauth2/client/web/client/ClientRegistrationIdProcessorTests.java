/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.service.invoker.HttpRequestValues;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ClientRegistrationIdProcessor}.
 *
 * @author Rob Winch
 * @since 7.0
 * @see ClientRegistrationIdProcessorWebClientTests
 * @see ClientRegistrationIdProcessorRestClientTests
 */
class ClientRegistrationIdProcessorTests {

	ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor.DEFAULT_INSTANCE;

	@Test
	void processWhenClientRegistrationIdPresentThenSet() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "hasClientRegistrationId");
		this.processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(RestService.REGISTRATION_ID);
	}

	@Test
	void processWhenMetaClientRegistrationIdPresentThenSet() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "hasMetaClientRegistrationId");
		this.processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(RestService.REGISTRATION_ID);
	}

	@Test
	void processWhenNoClientRegistrationIdPresentThenNull() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "noClientRegistrationId");
		this.processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isNull();
	}

	interface RestService {

		String REGISTRATION_ID = "registrationId";

		@ClientRegistrationId(REGISTRATION_ID)
		void hasClientRegistrationId();

		@MetaClientRegistrationId
		void hasMetaClientRegistrationId();

		void noClientRegistrationId();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@ClientRegistrationId(RestService.REGISTRATION_ID)
	@interface MetaClientRegistrationId {

	}

}

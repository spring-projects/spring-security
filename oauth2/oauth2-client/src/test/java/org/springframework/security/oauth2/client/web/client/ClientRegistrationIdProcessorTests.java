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

package org.springframework.security.oauth2.client.web.client;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.util.PlaceholderResolutionException;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringValueResolver;
import org.springframework.web.service.invoker.HttpRequestValues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Unit tests for {@link ClientRegistrationIdProcessor}.
 *
 * @author Rob Winch
 * @since 7.0
 * @see ClientRegistrationIdProcessorWebClientTests
 * @see ClientRegistrationIdProcessorRestClientTests
 */
class ClientRegistrationIdProcessorTests {

	private static final String REGISTRATION_ID = "registrationId";

	private static final String REGISTRATION_ID_PLACEHOLDER = "${test.registration-id}";

	ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor.DEFAULT_INSTANCE;

	@Test
	void processWhenClientRegistrationIdPresentThenSet() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "hasClientRegistrationId");
		this.processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenMetaClientRegistrationIdPresentThenSet() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "hasMetaClientRegistrationId");
		this.processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenNoClientRegistrationIdPresentThenNull() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "noClientRegistrationId");
		this.processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isNull();
	}

	@Test
	void processWhenClientRegistrationIdPresentOnDeclaringClassThenSet() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method declaringClassHasClientRegistrationId = ReflectionUtils.findMethod(TypeAnnotatedRestService.class,
				"declaringClassHasClientRegistrationId");
		this.processor.process(declaringClassHasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenDuplicateClientRegistrationIdPresentOnAggregateServiceThenException() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method shouldFailDueToDuplicateClientRegistrationId = ReflectionUtils.findMethod(AggregateRestService.class,
				"shouldFailDueToDuplicateClientRegistrationId");

		assertThatExceptionOfType(AnnotationConfigurationException.class).isThrownBy(
				() -> this.processor.process(shouldFailDueToDuplicateClientRegistrationId, null, null, builder));
	}

	@Test
	void processWhenEmbeddedValueResolverThenPlaceholderResolved() {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor
			.withEmbeddedValueResolver(embeddedValueResolver());
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasPlaceholder = ReflectionUtils.findMethod(RestService.class, "hasPlaceholderClientRegistrationId");
		processor.process(hasPlaceholder, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenEmbeddedValueResolverAndMetaAnnotationThenPlaceholderResolved() {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor
			.withEmbeddedValueResolver(embeddedValueResolver());
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasPlaceholder = ReflectionUtils.findMethod(RestService.class, "hasMetaPlaceholderClientRegistrationId");
		processor.process(hasPlaceholder, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenEmbeddedValueResolverAndDeclaringClassThenPlaceholderResolved() {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor
			.withEmbeddedValueResolver(embeddedValueResolver());
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasPlaceholder = ReflectionUtils.findMethod(PlaceholderTypeAnnotatedRestService.class,
				"declaringClassHasPlaceholderClientRegistrationId");
		processor.process(hasPlaceholder, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenEmbeddedValueResolverAndUnresolvablePlaceholderThenException() {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor
			.withEmbeddedValueResolver(embeddedValueResolver());
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method unresolvable = ReflectionUtils.findMethod(RestService.class, "hasUnresolvableClientRegistrationId");

		assertThatExceptionOfType(PlaceholderResolutionException.class)
			.isThrownBy(() -> processor.process(unresolvable, null, null, builder));
	}

	@Test
	void processWhenEmbeddedValueResolverResolvesToNullThenIllegalStateException() {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor
			.withEmbeddedValueResolver((value) -> null);
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasPlaceholder = ReflectionUtils.findMethod(RestService.class, "hasPlaceholderClientRegistrationId");

		assertThatIllegalStateException().isThrownBy(() -> processor.process(hasPlaceholder, null, null, builder))
			.withMessage("Could not resolve the client registration id from \"" + REGISTRATION_ID_PLACEHOLDER + "\"");
	}

	@Test
	void processWhenEmbeddedValueResolverAndNoPlaceholderThenValueUsed() {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor
			.withEmbeddedValueResolver(embeddedValueResolver());
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasClientRegistrationId = ReflectionUtils.findMethod(RestService.class, "hasClientRegistrationId");
		processor.process(hasClientRegistrationId, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void processWhenNoEmbeddedValueResolverThenPlaceholderNotResolved() {
		HttpRequestValues.Builder builder = HttpRequestValues.builder();
		Method hasPlaceholder = ReflectionUtils.findMethod(RestService.class, "hasPlaceholderClientRegistrationId");
		this.processor.process(hasPlaceholder, null, null, builder);

		String registrationId = ClientAttributes.resolveClientRegistrationId(builder.build().getAttributes());
		assertThat(registrationId).isEqualTo(REGISTRATION_ID_PLACEHOLDER);
	}

	@Test
	void withEmbeddedValueResolverWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ClientRegistrationIdProcessor.withEmbeddedValueResolver(null))
			.withMessage("embeddedValueResolver cannot be null");
	}

	private static StringValueResolver embeddedValueResolver() {
		StandardEnvironment environment = new StandardEnvironment();
		environment.getPropertySources()
			.addFirst(new MapPropertySource("test", Map.of("test.registration-id", REGISTRATION_ID)));
		return environment::resolveRequiredPlaceholders;
	}

	interface RestService {

		@ClientRegistrationId(REGISTRATION_ID)
		void hasClientRegistrationId();

		@ClientRegistrationId(REGISTRATION_ID_PLACEHOLDER)
		void hasPlaceholderClientRegistrationId();

		@ClientRegistrationId("${test.unknown-registration-id}")
		void hasUnresolvableClientRegistrationId();

		@MetaClientRegistrationId
		void hasMetaClientRegistrationId();

		@MetaPlaceholderClientRegistrationId
		void hasMetaPlaceholderClientRegistrationId();

		void noClientRegistrationId();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@ClientRegistrationId(REGISTRATION_ID)
	@interface MetaClientRegistrationId {

	}

	@Retention(RetentionPolicy.RUNTIME)
	@ClientRegistrationId(REGISTRATION_ID_PLACEHOLDER)
	@interface MetaPlaceholderClientRegistrationId {

	}

	@ClientRegistrationId(REGISTRATION_ID_PLACEHOLDER)
	interface PlaceholderTypeAnnotatedRestService {

		void declaringClassHasPlaceholderClientRegistrationId();

	}

	@ClientRegistrationId(REGISTRATION_ID)
	interface TypeAnnotatedRestService {

		void declaringClassHasClientRegistrationId();

	}

	@ClientRegistrationId("a")
	interface ARestService {

	}

	@ClientRegistrationId("b")
	interface BRestService {

	}

	interface AggregateRestService extends ARestService, BRestService {

		void shouldFailDueToDuplicateClientRegistrationId();

	}

}

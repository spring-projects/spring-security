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

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;

import org.springframework.core.MethodParameter;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.util.Assert;
import org.springframework.util.StringValueResolver;
import org.springframework.web.service.invoker.HttpRequestValues;

/**
 * Invokes {@link ClientAttributes#clientRegistrationId(String)} with the value specified
 * by {@link ClientRegistrationId} on the request.
 *
 * @author Rob Winch
 * @since 7.0
 */
public final class ClientRegistrationIdProcessor implements HttpRequestValues.Processor {

	/**
	 * An instance that uses the {@link ClientRegistrationId} value as is, without
	 * resolving property placeholders in it. Use
	 * {@link #withEmbeddedValueResolver(StringValueResolver)} to resolve them.
	 */
	public static ClientRegistrationIdProcessor DEFAULT_INSTANCE = new ClientRegistrationIdProcessor(null);

	private SecurityAnnotationScanner<ClientRegistrationId> securityAnnotationScanner = SecurityAnnotationScanners
		.requireUnique(ClientRegistrationId.class);

	private final @Nullable StringValueResolver embeddedValueResolver;

	private final Map<String, String> resolvedRegistrationIds = new ConcurrentHashMap<>();

	private ClientRegistrationIdProcessor(@Nullable StringValueResolver embeddedValueResolver) {
		this.embeddedValueResolver = embeddedValueResolver;
	}

	/**
	 * Creates an instance that resolves property placeholders such as
	 * <code>${my.client}</code> in the {@link ClientRegistrationId} value. The syntax is
	 * the same as for {@link org.springframework.web.service.annotation.HttpExchange}
	 * values, but each value is resolved on first use rather than when the HTTP service
	 * proxy is created.
	 * @param embeddedValueResolver the resolver used to resolve the value; cannot be
	 * null.
	 * @return a processor that resolves placeholders with the given resolver.
	 * @since 7.2
	 */
	public static ClientRegistrationIdProcessor withEmbeddedValueResolver(StringValueResolver embeddedValueResolver) {
		Assert.notNull(embeddedValueResolver, "embeddedValueResolver cannot be null");
		return new ClientRegistrationIdProcessor(embeddedValueResolver);
	}

	@Override
	public void process(Method method, MethodParameter[] parameters, @Nullable Object[] arguments,
			HttpRequestValues.Builder builder) {
		ClientRegistrationId registeredId = this.securityAnnotationScanner.scan(method, method.getDeclaringClass());

		if (registeredId != null) {
			String registrationId = resolveRegistrationId(registeredId.registrationId());
			builder.configureAttributes(ClientAttributes.clientRegistrationId(registrationId));
		}
	}

	private String resolveRegistrationId(String registrationId) {
		StringValueResolver resolver = this.embeddedValueResolver;
		if (resolver == null) {
			return registrationId;
		}
		return this.resolvedRegistrationIds.computeIfAbsent(registrationId, (value) -> {
			String resolved = resolver.resolveStringValue(value);
			Assert.state(resolved != null, () -> "Could not resolve the client registration id from \"" + value + "\"");
			return resolved;
		});
	}

}

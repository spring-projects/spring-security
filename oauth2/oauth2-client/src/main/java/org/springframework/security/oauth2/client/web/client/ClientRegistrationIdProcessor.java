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

import org.jspecify.annotations.Nullable;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.web.service.invoker.HttpRequestValues;

/**
 * Invokes {@link ClientAttributes#clientRegistrationId(String)} with the value specified
 * by {@link ClientRegistrationId} on the request.
 *
 * @author Rob Winch
 * @since 7.0
 */
public final class ClientRegistrationIdProcessor implements HttpRequestValues.Processor {

	public static ClientRegistrationIdProcessor DEFAULT_INSTANCE = new ClientRegistrationIdProcessor();

	@Override
	public void process(Method method, MethodParameter[] parameters, @Nullable Object[] arguments,
			HttpRequestValues.Builder builder) {
		ClientRegistrationId registeredId = AnnotationUtils.findAnnotation(method, ClientRegistrationId.class);
		if (registeredId != null) {
			String registrationId = registeredId.registrationId();
			builder.configureAttributes(ClientAttributes.clientRegistrationId(registrationId));
		}
	}

	private ClientRegistrationIdProcessor() {
	}

}

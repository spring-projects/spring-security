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

package org.springframework.security.authentication;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;

public final class AuthenticationObservationConvention
		implements ObservationConvention<AuthenticationObservationContext> {

	@Override
	public KeyValues getLowCardinalityKeyValues(AuthenticationObservationContext context) {
		KeyValues kvs = KeyValues.empty();
		if (context.getAuthenticationRequest() != null) {
			kvs = kvs.and("authentication.request.type", context.getAuthenticationRequest().getAuthenticationType());
		}
		if (context.getAuthenticationManager() != null) {
			kvs = kvs.and("authentication.method", context.getAuthenticationManager().getSimpleName());
		}
		if (context.getAuthenticationResult() != null) {
			kvs = kvs.and("authentication.result.type", context.getAuthenticationResult().getAuthenticationType());
		}
		if (context.getError().isPresent()) {
			kvs = kvs.and("authentication.failure.type", context.getError().get().getClass().getSimpleName());
		}
		return kvs;
	}

	@Override
	public boolean supportsContext(Observation.Context context) {
		return context instanceof AuthenticationObservationContext;
	}

}

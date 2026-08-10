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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import static org.mockito.Mockito.mock;

/**
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 5.1
 */
public class MockExchangeFunction implements ExchangeFunction {

	private final AtomicReference<Authentication> authenticationCaptor = new AtomicReference<>();

	private List<ClientRequest> requests = new ArrayList<>();

	private ClientResponse response = mock(ClientResponse.class);

	public Authentication getCapturedAuthentication() {
		return this.authenticationCaptor.get();
	}

	public ClientRequest getRequest() {
		return this.requests.get(this.requests.size() - 1);
	}

	public List<ClientRequest> getRequests() {
		return this.requests;
	}

	public ClientResponse getResponse() {
		return this.response;
	}

	@Override
	public Mono<ClientResponse> exchange(ClientRequest request) {
		return Mono.defer(() -> {
			this.requests.add(request);
			return captureAuthentication().then(Mono.just(this.response));
		});
	}

	private Mono<Authentication> captureAuthentication() {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.doOnNext(this.authenticationCaptor::set);
	}

}

/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interface which can be used to reject potentially dangerous requests and/or wrap them
 * to control their behaviour.
 * <p>
 * The implementation is injected into the {@code FilterChainProxy} and will be invoked
 * before sending any request through the filter chain. It can also provide a response
 * wrapper if the response behaviour should also be restricted.
 *
 * @author Luke Taylor
 */
public interface HttpFirewall {

	/**
	 * Provides the request object which will be passed through the filter chain.
	 * @throws RequestRejectedException if the request should be rejected immediately
	 */
	FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException;

	/**
	 * Provides the response which will be passed through the filter chain.
	 * @param response the original response
	 * @return either the original response or a replacement/wrapper.
	 */
	HttpServletResponse getFirewalledResponse(HttpServletResponse response);

}

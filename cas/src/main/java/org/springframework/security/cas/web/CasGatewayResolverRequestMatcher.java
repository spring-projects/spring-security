/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.cas.web;

import jakarta.servlet.http.HttpServletRequest;
import org.apereo.cas.client.authentication.DefaultGatewayResolverImpl;
import org.apereo.cas.client.authentication.GatewayResolver;

import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A {@link RequestMatcher} implementation that delegates the check to an instance of
 * {@link GatewayResolver}. The request is marked as "gatewayed" using the configured
 * {@link GatewayResolver} to avoid infinite loop.
 *
 * @author Michael Remond
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class CasGatewayResolverRequestMatcher implements RequestMatcher {

	private final ServiceProperties serviceProperties;

	private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();

	public CasGatewayResolverRequestMatcher(ServiceProperties serviceProperties) {
		Assert.notNull(serviceProperties, "serviceProperties cannot be null");
		this.serviceProperties = serviceProperties;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(request, this.serviceProperties.getService());
		if (!wasGatewayed) {
			this.gatewayStorage.storeGatewayInformation(request, this.serviceProperties.getService());
			return true;
		}
		return false;
	}

	/**
	 * Sets the {@link GatewayResolver} to check if the request was already gatewayed.
	 * Defaults to {@link DefaultGatewayResolverImpl}
	 * @param gatewayStorage the {@link GatewayResolver} to use. Cannot be null.
	 */
	public void setGatewayStorage(GatewayResolver gatewayStorage) {
		Assert.notNull(gatewayStorage, "gatewayStorage cannot be null");
		this.gatewayStorage = gatewayStorage;
	}

}

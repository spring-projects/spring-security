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

package org.springframework.security.web.firewall;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * A {@link RequestRejectedHandler} that delegates to several other
 * {@link RequestRejectedHandler}s.
 *
 * @author Adam Ostrožlík
 * @since 5.7
 */
public final class CompositeRequestRejectedHandler implements RequestRejectedHandler {

	private final List<RequestRejectedHandler> requestRejectedhandlers;

	/**
	 * Creates a new instance.
	 * @param requestRejectedhandlers the {@link RequestRejectedHandler} instances to
	 * handle {@link org.springframework.security.web.firewall.RequestRejectedException}
	 */
	public CompositeRequestRejectedHandler(RequestRejectedHandler... requestRejectedhandlers) {
		Assert.notEmpty(requestRejectedhandlers, "requestRejectedhandlers cannot be empty");
		this.requestRejectedhandlers = Arrays.asList(requestRejectedhandlers);
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			RequestRejectedException requestRejectedException) throws IOException, ServletException {
		for (RequestRejectedHandler requestRejectedhandler : this.requestRejectedhandlers) {
			requestRejectedhandler.handle(request, response, requestRejectedException);
		}
	}

}

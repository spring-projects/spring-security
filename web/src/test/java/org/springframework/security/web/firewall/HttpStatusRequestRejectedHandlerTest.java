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


import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

public class HttpStatusRequestRejectedHandlerTest {

	@Test
	public void httpStatusRequestRejectedHandlerUsesStatus400byDefault() throws Exception {
		//given:
		HttpStatusRequestRejectedHandler sut = new HttpStatusRequestRejectedHandler();
		HttpServletResponse response = mock(HttpServletResponse.class);

		//when:
		sut.handle(mock(HttpServletRequest.class), response, mock(RequestRejectedException.class));

		// then:
		verify(response).sendError(400);
	}

	@Test
	public void httpStatusRequestRejectedHandlerCanBeConfiguredToUseStatus() throws Exception {
		httpStatusRequestRejectedHandlerCanBeConfiguredToUseStatusHelper(400);
		httpStatusRequestRejectedHandlerCanBeConfiguredToUseStatusHelper(403);
		httpStatusRequestRejectedHandlerCanBeConfiguredToUseStatusHelper(500);
	}

	private void httpStatusRequestRejectedHandlerCanBeConfiguredToUseStatusHelper(int status) throws Exception {

		//given:
		HttpStatusRequestRejectedHandler sut = new HttpStatusRequestRejectedHandler(status);
		HttpServletResponse response = mock(HttpServletResponse.class);

		//when:
		sut.handle(mock(HttpServletRequest.class), response, mock(RequestRejectedException.class));

		// then:
		verify(response).sendError(status);
	}
}

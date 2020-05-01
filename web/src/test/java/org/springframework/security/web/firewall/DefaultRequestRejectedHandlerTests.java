/*
 * Copyright 2002-2020 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;

public class DefaultRequestRejectedHandlerTests {

	@Test
	public void defaultRequestRejectedHandlerRethrowsTheException() throws Exception {
		// given:
		RequestRejectedException requestRejectedException = new RequestRejectedException("rejected");
		DefaultRequestRejectedHandler sut = new DefaultRequestRejectedHandler();

		//when:
		try {
			sut.handle(mock(HttpServletRequest.class), mock(HttpServletResponse.class), requestRejectedException);
		} catch (RequestRejectedException exception) {
			//then:
			Assert.assertThat(exception.getMessage(), CoreMatchers.is("rejected"));
			return;
		}
		Assert.fail("Exception was not rethrown");
	}
}

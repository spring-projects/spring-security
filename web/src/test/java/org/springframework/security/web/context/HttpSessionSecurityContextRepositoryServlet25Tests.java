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

package org.springframework.security.web.context;

import javax.servlet.ServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ ClassUtils.class })
public class HttpSessionSecurityContextRepositoryServlet25Tests {
	@Test
	public void servlet25Compatability() throws Exception {
		spy(ClassUtils.class);
		when(ClassUtils.class, "hasMethod", ServletRequest.class, "startAsync",
				new Class[] {}).thenReturn(false);
		HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request,
				response);
		repo.loadContext(holder);
		assertThat(holder.getRequest()).isSameAs(request);
	}
}

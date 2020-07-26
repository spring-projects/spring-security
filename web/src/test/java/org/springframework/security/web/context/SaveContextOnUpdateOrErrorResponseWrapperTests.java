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

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class SaveContextOnUpdateOrErrorResponseWrapperTests {

	@Mock
	private SecurityContext securityContext;

	private MockHttpServletResponse response;

	private SaveContextOnUpdateOrErrorResponseWrapperStub wrappedResponse;

	@Before
	public void setUp() {
		this.response = new MockHttpServletResponse();
		this.wrappedResponse = new SaveContextOnUpdateOrErrorResponseWrapperStub(this.response, true);
		SecurityContextHolder.setContext(this.securityContext);
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void sendErrorSavesSecurityContext() throws Exception {
		int error = HttpServletResponse.SC_FORBIDDEN;
		this.wrappedResponse.sendError(error);
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
		assertThat(this.response.getStatus()).isEqualTo(error);
	}

	@Test
	public void sendErrorSkipsSaveSecurityContextDisables() throws Exception {
		final int error = HttpServletResponse.SC_FORBIDDEN;
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.sendError(error);
		assertThat(this.wrappedResponse.securityContext).isNull();
		assertThat(this.response.getStatus()).isEqualTo(error);
	}

	@Test
	public void sendErrorWithMessageSavesSecurityContext() throws Exception {
		int error = HttpServletResponse.SC_FORBIDDEN;
		String message = "Forbidden";
		this.wrappedResponse.sendError(error, message);
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
		assertThat(this.response.getStatus()).isEqualTo(error);
		assertThat(this.response.getErrorMessage()).isEqualTo(message);
	}

	@Test
	public void sendErrorWithMessageSkipsSaveSecurityContextDisables() throws Exception {
		final int error = HttpServletResponse.SC_FORBIDDEN;
		final String message = "Forbidden";
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.sendError(error, message);
		assertThat(this.wrappedResponse.securityContext).isNull();
		assertThat(this.response.getStatus()).isEqualTo(error);
		assertThat(this.response.getErrorMessage()).isEqualTo(message);
	}

	@Test
	public void sendRedirectSavesSecurityContext() throws Exception {
		String url = "/location";
		this.wrappedResponse.sendRedirect(url);
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
		assertThat(this.response.getRedirectedUrl()).isEqualTo(url);
	}

	@Test
	public void sendRedirectSkipsSaveSecurityContextDisables() throws Exception {
		final String url = "/location";
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.sendRedirect(url);
		assertThat(this.wrappedResponse.securityContext).isNull();
		assertThat(this.response.getRedirectedUrl()).isEqualTo(url);
	}

	@Test
	public void outputFlushSavesSecurityContext() throws Exception {
		this.wrappedResponse.getOutputStream().flush();
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
	}

	@Test
	public void outputFlushSkipsSaveSecurityContextDisables() throws Exception {
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.getOutputStream().flush();
		assertThat(this.wrappedResponse.securityContext).isNull();
	}

	@Test
	public void outputCloseSavesSecurityContext() throws Exception {
		this.wrappedResponse.getOutputStream().close();
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
	}

	@Test
	public void outputCloseSkipsSaveSecurityContextDisables() throws Exception {
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.getOutputStream().close();
		assertThat(this.wrappedResponse.securityContext).isNull();
	}

	@Test
	public void writerFlushSavesSecurityContext() throws Exception {
		this.wrappedResponse.getWriter().flush();
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
	}

	@Test
	public void writerFlushSkipsSaveSecurityContextDisables() throws Exception {
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.getWriter().flush();
		assertThat(this.wrappedResponse.securityContext).isNull();
	}

	@Test
	public void writerCloseSavesSecurityContext() throws Exception {
		this.wrappedResponse.getWriter().close();
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
	}

	@Test
	public void writerCloseSkipsSaveSecurityContextDisables() throws Exception {
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.getWriter().close();
		assertThat(this.wrappedResponse.securityContext).isNull();
	}

	@Test
	public void flushBufferSavesSecurityContext() throws Exception {
		this.wrappedResponse.flushBuffer();
		assertThat(this.wrappedResponse.securityContext).isEqualTo(this.securityContext);
	}

	@Test
	public void flushBufferSkipsSaveSecurityContextDisables() throws Exception {
		this.wrappedResponse.disableSaveOnResponseCommitted();
		this.wrappedResponse.flushBuffer();
		assertThat(this.wrappedResponse.securityContext).isNull();
	}

	private static class SaveContextOnUpdateOrErrorResponseWrapperStub
			extends SaveContextOnUpdateOrErrorResponseWrapper {

		private SecurityContext securityContext;

		SaveContextOnUpdateOrErrorResponseWrapperStub(HttpServletResponse response, boolean disableUrlRewriting) {
			super(response, disableUrlRewriting);
		}

		@Override
		protected void saveContext(SecurityContext context) {
			this.securityContext = context;
		}

	}

}

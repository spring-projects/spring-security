/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.taglibs.authz;

import jakarta.servlet.jsp.JspException;
import jakarta.servlet.jsp.tagext.Tag;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link AuthenticationTag}.
 *
 * @author Ben Alex
 */
public class AuthenticationTagTests {

	private final MyAuthenticationTag authenticationTag = new MyAuthenticationTag();

	private final Authentication auth = new TestingAuthenticationToken(
			new User("rodUserDetails", "koala", true, true, true, true, AuthorityUtils.NO_AUTHORITIES), "koala",
			AuthorityUtils.NO_AUTHORITIES);

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testOperationWhenPrincipalIsAUserDetailsInstance() throws JspException {
		SecurityContextHolder.getContext().setAuthentication(this.auth);
		this.authenticationTag.setProperty("name");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(this.authenticationTag.getLastMessage()).isEqualTo("rodUserDetails");
	}

	@Test
	public void testOperationWhenPrincipalIsAString() throws JspException {
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("rodAsString", "koala", AuthorityUtils.NO_AUTHORITIES));
		this.authenticationTag.setProperty("principal");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(this.authenticationTag.getLastMessage()).isEqualTo("rodAsString");
	}

	@Test
	public void testNestedPropertyIsReadCorrectly() throws JspException {
		SecurityContextHolder.getContext().setAuthentication(this.auth);
		this.authenticationTag.setProperty("principal.username");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(this.authenticationTag.getLastMessage()).isEqualTo("rodUserDetails");
	}

	@Test
	public void testOperationWhenPrincipalIsNull() throws JspException {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(null, "koala", AuthorityUtils.NO_AUTHORITIES));
		this.authenticationTag.setProperty("principal");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
	}

	@Test
	public void testOperationWhenSecurityContextIsNull() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(null);
		this.authenticationTag.setProperty("principal");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(this.authenticationTag.getLastMessage()).isNull();
	}

	@Test
	public void testSkipsBodyIfNullOrEmptyOperation() throws Exception {
		this.authenticationTag.setProperty("");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
	}

	@Test
	public void testThrowsExceptionForUnrecognisedProperty() {
		SecurityContextHolder.getContext().setAuthentication(this.auth);
		this.authenticationTag.setProperty("qsq");
		assertThatExceptionOfType(JspException.class).isThrownBy(() -> {
			this.authenticationTag.doStartTag();
			this.authenticationTag.doEndTag();
		});
	}

	@Test
	public void htmlEscapingIsUsedByDefault() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("<>& ", ""));
		this.authenticationTag.setProperty("name");
		this.authenticationTag.doStartTag();
		this.authenticationTag.doEndTag();
		assertThat(this.authenticationTag.getLastMessage()).isEqualTo("&lt;&gt;&amp;&#32;");
	}

	@Test
	public void settingHtmlEscapeToFalsePreventsEscaping() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("<>& ", ""));
		this.authenticationTag.setProperty("name");
		this.authenticationTag.setHtmlEscape("false");
		this.authenticationTag.doStartTag();
		this.authenticationTag.doEndTag();
		assertThat(this.authenticationTag.getLastMessage()).isEqualTo("<>& ");
	}

	@Test
	public void setSecurityContextHolderStrategyThenUses() throws Exception {
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(
				new TestingAuthenticationToken("rodAsString", "koala", AuthorityUtils.NO_AUTHORITIES)));
		MockServletContext servletContext = new MockServletContext();
		GenericWebApplicationContext applicationContext = new GenericWebApplicationContext();
		applicationContext.registerBean(SecurityContextHolderStrategy.class, () -> strategy);
		applicationContext.refresh();
		servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, applicationContext);
		this.authenticationTag.setPageContext(new MockPageContext(servletContext));
		this.authenticationTag.setProperty("principal");
		assertThat(this.authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(this.authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(this.authenticationTag.getLastMessage()).isEqualTo("rodAsString");
		verify(strategy).getContext();
	}

	private class MyAuthenticationTag extends AuthenticationTag {

		String lastMessage = null;

		String getLastMessage() {
			return this.lastMessage;
		}

		@Override
		protected void writeMessage(String msg) {
			this.lastMessage = msg;
		}

	}

}

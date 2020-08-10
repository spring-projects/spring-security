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

import static org.assertj.core.api.Assertions.*;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

/**
 * Tests {@link AuthenticationTag}.
 *
 * @author Ben Alex
 */
public class AuthenticationTagTests {

	// ~ Instance fields
	// ================================================================================================

	private final MyAuthenticationTag authenticationTag = new MyAuthenticationTag();

	private final Authentication auth = new TestingAuthenticationToken(
			new User("rodUserDetails", "koala", true, true, true, true, AuthorityUtils.NO_AUTHORITIES), "koala",
			AuthorityUtils.NO_AUTHORITIES);

	// ~ Methods
	// ========================================================================================================

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testOperationWhenPrincipalIsAUserDetailsInstance() throws JspException {
		SecurityContextHolder.getContext().setAuthentication(auth);

		authenticationTag.setProperty("name");
		assertThat(authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(authenticationTag.getLastMessage()).isEqualTo("rodUserDetails");
	}

	@Test
	public void testOperationWhenPrincipalIsAString() throws JspException {
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("rodAsString", "koala", AuthorityUtils.NO_AUTHORITIES));

		authenticationTag.setProperty("principal");
		assertThat(authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(authenticationTag.getLastMessage()).isEqualTo("rodAsString");
	}

	@Test
	public void testNestedPropertyIsReadCorrectly() throws JspException {
		SecurityContextHolder.getContext().setAuthentication(auth);

		authenticationTag.setProperty("principal.username");
		assertThat(authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(authenticationTag.getLastMessage()).isEqualTo("rodUserDetails");
	}

	@Test
	public void testOperationWhenPrincipalIsNull() throws JspException {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(null, "koala", AuthorityUtils.NO_AUTHORITIES));

		authenticationTag.setProperty("principal");
		assertThat(authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
	}

	@Test
	public void testOperationWhenSecurityContextIsNull() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(null);

		authenticationTag.setProperty("principal");
		assertThat(authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
		assertThat(authenticationTag.getLastMessage()).isNull();
	}

	@Test
	public void testSkipsBodyIfNullOrEmptyOperation() throws Exception {
		authenticationTag.setProperty("");
		assertThat(authenticationTag.doStartTag()).isEqualTo(Tag.SKIP_BODY);
		assertThat(authenticationTag.doEndTag()).isEqualTo(Tag.EVAL_PAGE);
	}

	@Test
	public void testThrowsExceptionForUnrecognisedProperty() {
		SecurityContextHolder.getContext().setAuthentication(auth);
		authenticationTag.setProperty("qsq");

		try {
			authenticationTag.doStartTag();
			authenticationTag.doEndTag();
			fail("Should have throwns JspException");
		}
		catch (JspException expected) {
		}
	}

	@Test
	public void htmlEscapingIsUsedByDefault() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("<>& ", ""));
		authenticationTag.setProperty("name");
		authenticationTag.doStartTag();
		authenticationTag.doEndTag();
		assertThat(authenticationTag.getLastMessage()).isEqualTo("&lt;&gt;&amp;&#32;");
	}

	@Test
	public void settingHtmlEscapeToFalsePreventsEscaping() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("<>& ", ""));
		authenticationTag.setProperty("name");
		authenticationTag.setHtmlEscape("false");
		authenticationTag.doStartTag();
		authenticationTag.doEndTag();
		assertThat(authenticationTag.getLastMessage()).isEqualTo("<>& ");
	}

	// ~ Inner Classes
	// ==================================================================================================

	private class MyAuthenticationTag extends AuthenticationTag {

		String lastMessage = null;

		public String getLastMessage() {
			return lastMessage;
		}

		protected void writeMessage(String msg) {
			lastMessage = msg;
		}

	}

}

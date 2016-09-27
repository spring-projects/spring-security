/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.taglibs.redirect;

import java.io.UnsupportedEncodingException;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.redirect.SignCalculator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RedirectorTagTests {

	@Mock
	private SignCalculator signCalculator;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private RedirectorTag redirectorTag;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.redirectorTag = new RedirectorTag();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setTargetUrlNull(){
		this.redirectorTag.setTargetUrl(null);
	}

	@Test(expected = JspException.class)
	public void setRedirectorUrlNull() throws JspException{
		this.redirectorTag.setRedirectorUrl(null);
		this.redirectorTag.setHidden(false);
		this.redirectorTag.doEndTag();
	}

	@Test
	public void doEndTagRendersHiddenFields() throws JspException,
			UnsupportedEncodingException {
		String targetUrl = "https://spring.io";
		when(this.signCalculator.calculateSign(targetUrl)).thenReturn(
				"calculated_sign");

		MockServletContext servletContext = new MockServletContext();
		this.request.setAttribute("_redirectParameter", "redirectTo");
		this.request.setAttribute("_signParameter", "sign");
		this.request.setAttribute("_signCalculator", this.signCalculator);
		MockPageContext pageContext = new MockPageContext(servletContext,
				this.request, this.response);
		this.redirectorTag.setPageContext(pageContext);
		this.redirectorTag.setTargetUrl(targetUrl);
		this.redirectorTag.setHidden(true);

		assertThat(this.redirectorTag.doEndTag()).isEqualTo(
				TagSupport.EVAL_PAGE);
		assertThat(this.response.getContentAsString())
				.isEqualTo(
						"<input type=\"hidden\" name=\"redirectTo\" "
						+ "value=\"https://spring.io\" />\n"
						+ "<input type=\"hidden\" name=\"sign\" "
						+ "value=\"calculated_sign\" />");
	}

	@Test
	public void doEndTagRendersLinkToRedirector() throws JspException,
			UnsupportedEncodingException {
		String targetUrl = "https://spring.io";
		when(this.signCalculator.calculateSign(targetUrl)).thenReturn(
				"calculated_sign");

		MockServletContext servletContext = new MockServletContext();
		this.request.setAttribute("_redirectParameter", "redirectTo");
		this.request.setAttribute("_signParameter", "sign");
		this.request.setAttribute("_signCalculator", this.signCalculator);
		MockPageContext pageContext = new MockPageContext(servletContext,
				this.request, this.response);
		this.redirectorTag.setPageContext(pageContext);
		this.redirectorTag.setTargetUrl(targetUrl);
		this.redirectorTag.setRedirectorUrl("redirector");
		this.redirectorTag.setHidden(false);
		this.redirectorTag.setText("link");

		assertThat(this.redirectorTag.doEndTag()).isEqualTo(
				TagSupport.EVAL_PAGE);
		assertThat(this.response.getContentAsString())
				.isEqualTo(
						"<a href=\"redirector?redirectTo=https://spring.io"
						+ "&sign=calculated_sign\">link</a>");
	}

}
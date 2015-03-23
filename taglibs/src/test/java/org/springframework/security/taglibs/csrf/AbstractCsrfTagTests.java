package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.*;

/**
 * @author Nick Williams
 */
public class AbstractCsrfTagTests {

	public MockTag tag;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;

	@Before
	public void setUp() {
		MockServletContext servletContext = new MockServletContext();
		this.request = new MockHttpServletRequest(servletContext);
		this.response = new MockHttpServletResponse();
		MockPageContext pageContext = new MockPageContext(servletContext, this.request,
				this.response);
		this.tag = new MockTag();
		this.tag.setPageContext(pageContext);
	}

	@Test
	public void noCsrfDoesNotRender() throws JspException, UnsupportedEncodingException {

		this.tag.handleReturn = "shouldNotBeRendered";

		int returned = this.tag.doEndTag();

		assertEquals("The returned value is not correct.", TagSupport.EVAL_PAGE, returned);
		assertEquals("The output value is not correct.", "",
				this.response.getContentAsString());
	}

	@Test
	public void hasCsrfRendersReturnedValue() throws JspException,
			UnsupportedEncodingException {

		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf",
				"abc123def456ghi789");
		this.request.setAttribute(CsrfToken.class.getName(), token);

		this.tag.handleReturn = "fooBarBazQux";

		int returned = this.tag.doEndTag();

		assertEquals("The returned value is not correct.", TagSupport.EVAL_PAGE, returned);
		assertEquals("The output value is not correct.", "fooBarBazQux",
				this.response.getContentAsString());
		assertSame("The token is not correct.", token, this.tag.token);
	}

	@Test
	public void hasCsrfRendersDifferentValue() throws JspException,
			UnsupportedEncodingException {

		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf",
				"abc123def456ghi789");
		this.request.setAttribute(CsrfToken.class.getName(), token);

		this.tag.handleReturn = "<input type=\"hidden\" />";

		int returned = this.tag.doEndTag();

		assertEquals("The returned value is not correct.", TagSupport.EVAL_PAGE, returned);
		assertEquals("The output value is not correct.", "<input type=\"hidden\" />",
				this.response.getContentAsString());
		assertSame("The token is not correct.", token, this.tag.token);
	}

	private static class MockTag extends AbstractCsrfTag {

		private CsrfToken token;
		private String handleReturn;

		@Override
		protected String handleToken(CsrfToken token) {
			this.token = token;
			return this.handleReturn;
		}
	}
}

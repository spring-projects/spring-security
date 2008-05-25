package org.springframework.security.wrapper;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.savedrequest.SavedRequest;
import org.springframework.security.util.PortResolverImpl;

public class SavedRequestAwareWrapperTests {
	
	@Test
	/* SEC-830 */
	public void wrappedRequestParameterTakesPrecedenceOverSavedRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("action", "foo");
		SavedRequest savedRequest = new SavedRequest(request, new PortResolverImpl());
		MockHttpServletRequest request2 = new MockHttpServletRequest();
		request2.getSession().setAttribute(AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest);
		SavedRequestAwareWrapper wrapper = new SavedRequestAwareWrapper(request2, new PortResolverImpl(), "ROLE_");
		assertEquals("foo", wrapper.getParameter("action"));
		request2.setParameter("action", "bar");
		assertEquals("bar", wrapper.getParameter("action"));
	}
	
	@Test
	public void savedRequestHeadersTakePrecedence() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization","foo");
		SavedRequest savedRequest = new SavedRequest(request, new PortResolverImpl());

		MockHttpServletRequest request2 = new MockHttpServletRequest();
		request2.addHeader("Authorization","bar");
		request2.getSession().setAttribute(AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest);

		SavedRequestAwareWrapper wrapper = new SavedRequestAwareWrapper(request2, new PortResolverImpl(), "ROLE_");

		assertEquals("foo", wrapper.getHeader("Authorization"));
	}
}

package org.springframework.security.wrapper;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.savedrequest.SavedRequest;
import org.springframework.security.util.PortResolverImpl;

public class SavedRequestAwareWrapperTests {
	
	@Test
	/* SEC-830. Assume we have a request to /someUrl?action=foo (the saved request) 
	 * and then RequestDispatcher.forward() it to /someUrl?action=bar.
	 * What should action parameter be before and during the forward?
	 **/
	public void wrappedRequestParameterTakesPrecedenceOverSavedRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("action", "foo");
		SavedRequest savedRequest = new SavedRequest(request, new PortResolverImpl());
		MockHttpServletRequest request2 = new MockHttpServletRequest();
		request2.getSession().setAttribute(AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest);
		SavedRequestAwareWrapper wrapper = new SavedRequestAwareWrapper(request2, new PortResolverImpl(), "ROLE_");
		assertEquals("foo", wrapper.getParameter("action"));
		// The request after forward
		request2.setParameter("action", "bar");
		assertEquals("bar", wrapper.getParameter("action"));
		// Both values should be set, but "bar" should be first
		assertEquals(2, wrapper.getParameterValues("action").length);
		assertEquals("bar", wrapper.getParameterValues("action")[0]);
	}

	@Test
	public void savedRequestDoesntCreateDuplicateParams() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("action", "foo");
		SavedRequest savedRequest = new SavedRequest(request, new PortResolverImpl());
		MockHttpServletRequest request2 = new MockHttpServletRequest();
		request2.getSession().setAttribute(AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest);
		request2.setParameter("action", "foo");
		SavedRequestAwareWrapper wrapper = new SavedRequestAwareWrapper(request2, new PortResolverImpl(), "ROLE_");
		assertEquals(1, wrapper.getParameterValues("action").length);
		assertEquals(1, wrapper.getParameterMap().size());
		assertEquals(1, ((String[])wrapper.getParameterMap().get("action")).length);
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

	@Test
	public void getParameterValuesReturnsNullIfParameterIsntSet() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		SavedRequestAwareWrapper wrapper = new SavedRequestAwareWrapper(request, new PortResolverImpl(), "ROLE_");
		assertNull(wrapper.getParameterValues("action"));
		assertNull(wrapper.getParameterMap().get("action"));
	}
	
	@Test
	public void getParameterValuesReturnsCombinedValues() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("action", "foo");
		SavedRequest savedRequest = new SavedRequest(request, new PortResolverImpl());
		MockHttpServletRequest request2 = new MockHttpServletRequest();
		request2.getSession().setAttribute(AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest);
		SavedRequestAwareWrapper wrapper = new SavedRequestAwareWrapper(request2, new PortResolverImpl(), "ROLE_");
		assertArrayEquals(new Object[] {"foo"}, wrapper.getParameterValues("action"));
		request2.setParameter("action", "bar");
		assertArrayEquals(new Object[] {"bar","foo"}, wrapper.getParameterValues("action"));
		// Check map is consistent
		String[] valuesFromMap = (String[]) wrapper.getParameterMap().get("action"); 
		assertEquals(2, valuesFromMap.length);
		assertEquals("bar", valuesFromMap[0]);
	}
}

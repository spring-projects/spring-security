/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.savedrequest;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.http.Cookie;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.PortResolverImpl;

import static org.assertj.core.api.Assertions.assertThat;

public class SavedRequestAwareWrapperTests {

	private SavedRequestAwareWrapper createWrapper(MockHttpServletRequest requestToSave,
			MockHttpServletRequest requestToWrap) {
		DefaultSavedRequest saved = new DefaultSavedRequest(requestToSave, new PortResolverImpl());
		return new SavedRequestAwareWrapper(saved, requestToWrap);
	}

	// SEC-2569
	@Test
	public void savedRequestCookiesAreIgnored() {
		MockHttpServletRequest newRequest = new MockHttpServletRequest();
		newRequest.setCookies(new Cookie[] { new Cookie("cookie", "fromnew") });
		MockHttpServletRequest savedRequest = new MockHttpServletRequest();
		savedRequest.setCookies(new Cookie[] { new Cookie("cookie", "fromsaved") });
		SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, newRequest);
		assertThat(wrapper.getCookies()).hasSize(1);
		assertThat(wrapper.getCookies()[0].getValue()).isEqualTo("fromnew");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void savedRequesthHeaderIsReturnedIfSavedRequestIsSet() {
		MockHttpServletRequest savedRequest = new MockHttpServletRequest();
		savedRequest.addHeader("header", "savedheader");
		SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, new MockHttpServletRequest());
		assertThat(wrapper.getHeader("nonexistent")).isNull();
		Enumeration headers = wrapper.getHeaders("nonexistent");
		assertThat(headers.hasMoreElements()).isFalse();
		assertThat(wrapper.getHeader("Header")).isEqualTo("savedheader");
		headers = wrapper.getHeaders("heaDer");
		assertThat(headers.hasMoreElements()).isTrue();
		assertThat(headers.nextElement()).isEqualTo("savedheader");
		assertThat(headers.hasMoreElements()).isFalse();
		assertThat(wrapper.getHeaderNames().hasMoreElements()).isTrue();
		assertThat(wrapper.getHeaderNames().nextElement()).isEqualTo("header");
	}

	@Test
	/*
	 * SEC-830. Assume we have a request to /someUrl?action=foo (the saved request) and
	 * then RequestDispatcher.forward() it to /someUrl?action=bar. What should action
	 * parameter be before and during the forward?
	 */
	public void wrappedRequestParameterTakesPrecedenceOverSavedRequest() {
		MockHttpServletRequest savedRequest = new MockHttpServletRequest();
		savedRequest.setParameter("action", "foo");
		MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
		SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
		assertThat(wrapper.getParameter("action")).isEqualTo("foo");
		// The request after forward
		wrappedRequest.setParameter("action", "bar");
		assertThat(wrapper.getParameter("action")).isEqualTo("bar");
		// Both values should be set, but "bar" should be first
		assertThat(wrapper.getParameterValues("action")).hasSize(2);
		assertThat(wrapper.getParameterValues("action")[0]).isEqualTo("bar");
	}

	@Test
	public void savedRequestDoesntCreateDuplicateParams() {
		MockHttpServletRequest savedRequest = new MockHttpServletRequest();
		savedRequest.setParameter("action", "foo");
		MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
		wrappedRequest.setParameter("action", "foo");
		SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
		assertThat(wrapper.getParameterValues("action")).hasSize(1);
		assertThat(wrapper.getParameterMap()).hasSize(1);
		assertThat(((String[]) wrapper.getParameterMap().get("action"))).hasSize(1);
	}

	@Test
	public void savedRequestHeadersTakePrecedence() {
		MockHttpServletRequest savedRequest = new MockHttpServletRequest();
		savedRequest.addHeader("Authorization", "foo");
		MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
		wrappedRequest.addHeader("Authorization", "bar");
		SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
		assertThat(wrapper.getHeader("Authorization")).isEqualTo("foo");
	}

	@Test
	public void getParameterValuesReturnsNullIfParameterIsntSet() {
		SavedRequestAwareWrapper wrapper = createWrapper(new MockHttpServletRequest(), new MockHttpServletRequest());
		assertThat(wrapper.getParameterValues("action")).isNull();
		assertThat(wrapper.getParameterMap().get("action")).isNull();
	}

	@Test
	public void getParameterValuesReturnsCombinedSavedAndWrappedRequestValues() {
		MockHttpServletRequest savedRequest = new MockHttpServletRequest();
		savedRequest.setParameter("action", "foo");
		MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
		SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
		assertThat(wrapper.getParameterValues("action")).isEqualTo(new Object[] { "foo" });
		wrappedRequest.setParameter("action", "bar");
		assertThat(wrapper.getParameterValues("action")).isEqualTo(new Object[] { "bar", "foo" });
		// Check map is consistent
		String[] valuesFromMap = (String[]) wrapper.getParameterMap().get("action");
		assertThat(valuesFromMap).hasSize(2);
		assertThat(valuesFromMap[0]).isEqualTo("bar");
	}

	@Test
	public void expecteDateHeaderIsReturnedFromSavedRequest() throws Exception {
		SimpleDateFormat formatter = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
		String nowString = FastHttpDateFormat.getCurrentDate();
		Date now = formatter.parse(nowString);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("header", nowString);
		SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest());
		assertThat(wrapper.getDateHeader("header")).isEqualTo(now.getTime());
		assertThat(wrapper.getDateHeader("nonexistent")).isEqualTo(-1L);
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidDateHeaderIsRejected() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("header", "notadate");
		SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest());
		wrapper.getDateHeader("header");
	}

	@Test
	public void correctHttpMethodIsReturned() {
		MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/notused");
		SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest("GET", "/notused"));
		assertThat(wrapper.getMethod()).isEqualTo("PUT");
	}

	@Test
	public void correctIntHeaderIsReturned() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("header", "999");
		request.addHeader("header", "1000");
		SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest());
		assertThat(wrapper.getIntHeader("header")).isEqualTo(999);
		assertThat(wrapper.getIntHeader("nonexistent")).isEqualTo(-1);
	}

}

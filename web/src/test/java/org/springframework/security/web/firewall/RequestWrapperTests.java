/*
 * Copyright 2004-present the original author or authors.
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

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Luke Taylor
 */
public class RequestWrapperTests {

	private static Map<String, String> testPaths = new LinkedHashMap<>();

	@BeforeAll
	// Some of these may be unrealistic values, but we can't be sure because of the
	// inconsistency in the spec.
	public static void createTestMap() {
		testPaths.put("/path1;x=y;z=w/path2;x=y/path3;x=y", "/path1/path2/path3");
		testPaths.put("/path1;x=y/path2;x=y/", "/path1/path2/");
		testPaths.put("/path1//path2/", "/path1/path2/");
		testPaths.put("//path1/path2//", "/path1/path2/");
		testPaths.put(";x=y;z=w", "");
	}

	@Test
	public void pathParametersAreRemovedFromServletPath() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		for (Map.Entry<String, String> entry : testPaths.entrySet()) {
			String path = entry.getKey();
			String expectedResult = entry.getValue();
			request.setServletPath(path);
			RequestWrapper wrapper = new RequestWrapper(request);
			assertThat(wrapper.getServletPath()).isEqualTo(expectedResult);
			wrapper.reset();
			assertThat(wrapper.getServletPath()).isEqualTo(path);
		}
	}

	@Test
	public void pathParametersAreRemovedFromPathInfo() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		for (Map.Entry<String, String> entry : testPaths.entrySet()) {
			String path = entry.getKey();
			String expectedResult = entry.getValue();
			// Should be null when stripped value is empty
			if (expectedResult.isEmpty()) {
				expectedResult = null;
			}
			request.setPathInfo(path);
			RequestWrapper wrapper = new RequestWrapper(request);
			assertThat(wrapper.getPathInfo()).isEqualTo(expectedResult);
			wrapper.reset();
			assertThat(wrapper.getPathInfo()).isEqualTo(path);
		}
	}

	@Test
	public void resetWhenForward() throws Exception {
		String denormalizedPath = testPaths.keySet().iterator().next();
		String forwardPath = "/forward/path";
		HttpServletRequest mockRequest = mock(HttpServletRequest.class);
		HttpServletResponse mockResponse = mock(HttpServletResponse.class);
		RequestDispatcher mockDispatcher = mock(RequestDispatcher.class);
		given(mockRequest.getServletPath()).willReturn("");
		given(mockRequest.getPathInfo()).willReturn(denormalizedPath);
		given(mockRequest.getRequestDispatcher(forwardPath)).willReturn(mockDispatcher);
		RequestWrapper wrapper = new RequestWrapper(mockRequest);
		RequestDispatcher dispatcher = wrapper.getRequestDispatcher(forwardPath);
		dispatcher.forward(mockRequest, mockResponse);
		verify(mockRequest).getRequestDispatcher(forwardPath);
		verify(mockDispatcher).forward(mockRequest, mockResponse);
		assertThat(wrapper.getPathInfo()).isEqualTo(denormalizedPath);
		verify(mockRequest, times(2)).getPathInfo();
		// validate wrapper.getServletPath() delegates to the mock
		wrapper.getServletPath();
		verify(mockRequest, times(2)).getServletPath();
		verifyNoMoreInteractions(mockRequest, mockResponse, mockDispatcher);
	}

	@Test
	public void requestDispatcherNotWrappedAfterReset() {
		String path = "/forward/path";
		HttpServletRequest request = mock(HttpServletRequest.class);
		RequestDispatcher dispatcher = mock(RequestDispatcher.class);
		given(request.getRequestDispatcher(path)).willReturn(dispatcher);
		RequestWrapper wrapper = new RequestWrapper(request);
		wrapper.reset();
		assertThat(wrapper.getRequestDispatcher(path)).isSameAs(dispatcher);
	}

}

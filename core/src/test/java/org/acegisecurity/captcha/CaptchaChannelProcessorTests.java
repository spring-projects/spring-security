/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.captcha;

import java.io.IOException;

import javax.servlet.ServletException;

import junit.framework.TestCase;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.MockFilterChain;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.intercept.web.FilterInvocation;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** 
 * Tests {@link CaptchaChannelProcessor} 
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaChannelProcessorTests extends TestCase {

	public void testDecideRequestsFirstTestRequests() throws Exception {
		ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
		cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
		cad.addConfigAttribute(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_REQUESTS"));

		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);

		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		CaptchaEntryPoint epoint = new CaptchaEntryPoint();
		epoint.setCaptchaFormUrl("/jcaptcha.do");
		processor.setEntryPoint(epoint);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/demo");
		request.setServletPath("/restricted");
		request.setScheme("http");
		request.setServerPort(8000);

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		processor.decide(fi, cad);
		assertEquals(response.getRedirectedUrl(),
				"http://localhost:8000/demo/jcaptcha.do");

		processor.setMaxRequestsBeforeFirstTest(1);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(response.getRedirectedUrl(), null);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(response.getRedirectedUrl(),
				"http://localhost:8000/demo/jcaptcha.do");

		processor.setMaxRequestsBeforeFirstTest(2);
		processor.setMaxMillisBeforeReTest(0);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());
	}

	public void testDecideRequestsFirstTestMillis() throws Exception {
		ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
		cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
		cad.addConfigAttribute(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_MILLIS"));

		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);

		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		CaptchaEntryPoint epoint = new CaptchaEntryPoint();
		epoint.setCaptchaFormUrl("/jcaptcha.do");
		processor.setEntryPoint(epoint);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/demo");
		request.setServletPath("/restricted");
		request.setScheme("http");
		request.setServerPort(8000);

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		processor.decide(fi, cad);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeFirstTest(1);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeFirstTest(2);
		processor.setMaxRequestsBeforeReTest(0);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

	}

	public void testDecideRequestsReTest() throws Exception {
		ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
		cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
		cad.addConfigAttribute(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_REQUESTS"));

		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);

		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		CaptchaEntryPoint epoint = new CaptchaEntryPoint();
		epoint.setCaptchaFormUrl("/jcaptcha.do");
		processor.setEntryPoint(epoint);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/demo");
		request.setServletPath("/restricted");
		request.setScheme("http");
		request.setServerPort(8000);

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		processor.decide(fi, cad);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeFirstTest(1);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(response.getRedirectedUrl(), null);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeReTest(2);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxMillisBeforeReTest(0);
		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());
	}

	private MockHttpServletResponse decideWithNewResponse(
			ConfigAttributeDefinition cad, CaptchaChannelProcessor processor,
			MockHttpServletRequest request) throws IOException,
			ServletException {
		MockHttpServletResponse response;
		MockFilterChain chain;
		FilterInvocation fi;
		response = new MockHttpServletResponse();
		chain = new MockFilterChain();
		fi = new FilterInvocation(request, response, chain);
		processor.decide(fi, cad);
		return response;
	}

	public void testDecideRejectsNulls() throws Exception {
		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		processor.setEntryPoint(new CaptchaEntryPoint());
		processor.afterPropertiesSet();

		try {
			processor.decide(null, null);
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException expected) {
			assertTrue(true);
		}
	}
/*
  
 // TODO: Re-enable these tests.
  
   Commented out by Ben Alex on 19 Sep 05 as the Thread.sleep(100) approach to simulating
   request age caused intermittent problems. An alternative approach should be used
   instead, such as (a) modifying the CaptchaSecurityContextImpl (why not make a package
   protected setLastPassedCaptchaDateInMillis) or (b) providing a package protected method
   so that the unit test can modify the time being used by CaptchaChannelProcesor instead
   of using System.currentTimeMillis().
   
	public void testDecideMillis() throws Exception {
		ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
		cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
		cad.addConfigAttribute(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_MILLIS"));

		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);

		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		CaptchaEntryPoint epoint = new CaptchaEntryPoint();
		epoint.setCaptchaFormUrl("/jcaptcha.do");
		processor.setEntryPoint(epoint);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/demo");
		request.setServletPath("/restricted");
		request.setScheme("http");
		request.setServerPort(8000);

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		processor.decide(fi, cad);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeFirstTest(1);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(response.getRedirectedUrl(), null);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxMillisBeforeReTest(100);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		Thread.sleep(100);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeReTest(0);
		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		Thread.sleep(100);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		Thread.sleep(100);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());
	}

	public void testDecideBoth() throws Exception {
		ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
		cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
		cad.addConfigAttribute(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_MILLIS"));
		cad.addConfigAttribute(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_REQUESTS"));

		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);

		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		CaptchaEntryPoint epoint = new CaptchaEntryPoint();
		epoint.setCaptchaFormUrl("/jcaptcha.do");
		processor.setEntryPoint(epoint);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/demo");
		request.setServletPath("/restricted");
		request.setScheme("http");
		request.setServerPort(8000);

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		processor.decide(fi, cad);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxRequestsBeforeFirstTest(1);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(response.getRedirectedUrl(), null);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		processor.setMaxMillisBeforeReTest(100);
		processor.setMaxRequestsBeforeReTest(2);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		Thread.sleep(100);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		context.setHuman();
		SecurityContextHolder.setContext(context);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals(null, response.getRedirectedUrl());

		Thread.sleep(100);

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());

		response = decideWithNewResponse(cad, processor, request);
		assertEquals("http://localhost:8000/demo/jcaptcha.do", response
				.getRedirectedUrl());
	}
*/
	public void testGettersSetters() {
		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		assertEquals("REQUIRES_HUMAN_AFTER_MAX_MILLIS", processor
				.getRequiresHumanAfterMaxMillisKeyword());
		processor.setRequiresHumanAfterMaxMillisKeyword("X");
		assertEquals("X", processor.getRequiresHumanAfterMaxMillisKeyword());

		assertEquals("REQUIRES_HUMAN_AFTER_MAX_REQUESTS", processor
				.getRequiresHumanAfterMaxRequestsKeyword());
		processor.setRequiresHumanAfterMaxRequestsKeyword("Y");
		assertEquals("Y", processor.getRequiresHumanAfterMaxRequestsKeyword());

		assertEquals(0, processor.getMaxRequestsBeforeFirstTest());
		processor.setMaxRequestsBeforeFirstTest(1);
		assertEquals(1, processor.getMaxRequestsBeforeFirstTest());

		assertEquals(-1, processor.getMaxRequestsBeforeReTest());
		processor.setMaxRequestsBeforeReTest(11);
		assertEquals(11, processor.getMaxRequestsBeforeReTest());

		assertEquals(-1, processor.getMaxMillisBeforeReTest());
		processor.setMaxMillisBeforeReTest(111);
		assertEquals(111, processor.getMaxMillisBeforeReTest());

		assertTrue(processor.getEntryPoint() == null);
		processor.setEntryPoint(new CaptchaEntryPoint());
		assertTrue(processor.getEntryPoint() != null);
	}

	public void testMissingEntryPoint() throws Exception {
		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		processor.setEntryPoint(null);

		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException expected) {
			assertEquals("entryPoint required", expected.getMessage());
		}
	}

	public void testMissingKeyword() throws Exception {
		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		processor.setRequiresHumanAfterMaxMillisKeyword(null);

		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException expected) {

		}
		processor.setRequiresHumanAfterMaxMillisKeyword("");

		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException expected) {

		}
		processor.setRequiresHumanAfterMaxRequestsKeyword("");

		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException expected) {

		}

		processor.setRequiresHumanAfterMaxRequestsKeyword(null);

		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException expected) {

		}

	}

	public void testSupports() {
		CaptchaChannelProcessor processor = new CaptchaChannelProcessor();
		assertTrue(processor.supports(new SecurityConfig(processor
				.getRequiresHumanAfterMaxMillisKeyword())));
		assertTrue(processor.supports(new SecurityConfig(processor
				.getRequiresHumanAfterMaxRequestsKeyword())));

		assertTrue(processor.supports(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_REQUESTS")));
		assertTrue(processor.supports(new SecurityConfig(
				"REQUIRES_HUMAN_AFTER_MAX_MILLIS")));

		assertFalse(processor.supports(null));

		assertFalse(processor.supports(new SecurityConfig("NOT_SUPPORTED")));
	}

}

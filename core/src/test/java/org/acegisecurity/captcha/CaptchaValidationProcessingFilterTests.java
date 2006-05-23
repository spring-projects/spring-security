/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.captcha;

import junit.framework.TestCase;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.util.MockFilterChain;

import org.springframework.mock.web.MockHttpServletRequest;


/**
 * Tests {@link CaptchaValidationProcessingFilter}.
 *
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaValidationProcessingFilterTests extends TestCase {
    //~ Methods ========================================================================================================

    /*
     */
    public void testAfterPropertiesSet() throws Exception {
        CaptchaValidationProcessingFilter filter = new CaptchaValidationProcessingFilter();

        try {
            filter.afterPropertiesSet();
            fail("should have thrown an invalid argument exception");
        } catch (Exception e) {
            assertTrue("should be an InvalidArgumentException",
                IllegalArgumentException.class.isAssignableFrom(e.getClass()));
        }

        filter.setCaptchaService(new MockCaptchaServiceProxy());
        filter.afterPropertiesSet();
        filter.setCaptchaValidationParameter(null);

        try {
            filter.afterPropertiesSet();
            fail("should have thrown an invalid argument exception");
        } catch (Exception e) {
            assertTrue("should be an InvalidArgumentException",
                IllegalArgumentException.class.isAssignableFrom(e.getClass()));
        }
    }

    /*
     * Test method for
     * 'org.acegisecurity.captcha.CaptchaValidationProcessingFilter.doFilter(ServletRequest,
     * ServletResponse, FilterChain)'
     */
    public void testDoFilterWithRequestParameter() throws Exception {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        SecurityContextHolder.setContext(context);

        MockHttpServletRequest request = new MockHttpServletRequest();

        CaptchaValidationProcessingFilter filter = new CaptchaValidationProcessingFilter();
        request.addParameter(filter.getCaptchaValidationParameter(), "");

        MockCaptchaServiceProxy service = new MockCaptchaServiceProxy();
        MockFilterChain chain = new MockFilterChain(true);
        filter.setCaptchaService(service);
        filter.doFilter(request, null, chain);
        assertTrue("should have been called", service.hasBeenCalled);
        assertFalse("context should not have been updated", context.isHuman());

        // test with valid
        service.valid = true;
        filter.doFilter(request, null, chain);
        assertTrue("should have been called", service.hasBeenCalled);
        assertTrue("context should have been updated", context.isHuman());
    }

    /*
     * Test method for
     * 'org.acegisecurity.captcha.CaptchaValidationProcessingFilter.doFilter(ServletRequest,
     * ServletResponse, FilterChain)'
     */
    public void testDoFilterWithoutRequestParameter() throws Exception {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        SecurityContextHolder.setContext(context);

        MockHttpServletRequest request = new MockHttpServletRequest();
        CaptchaValidationProcessingFilter filter = new CaptchaValidationProcessingFilter();
        MockCaptchaServiceProxy service = new MockCaptchaServiceProxy();
        MockFilterChain chain = new MockFilterChain(true);
        filter.setCaptchaService(service);
        filter.doFilter(request, null, chain);
        assertFalse("proxy should not have been called", service.hasBeenCalled);
        assertFalse("context should not have been updated", context.isHuman());

        // test with valid
        service.valid = true;
        filter.doFilter(request, null, chain);
        assertFalse("proxy should not have been called", service.hasBeenCalled);
        assertFalse("context should not have been updated", context.isHuman());
    }
}

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

package org.springframework.security.wrapper;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletResponse;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.PortResolverImpl;


/**
 * Tests {@link SecurityContextHolderAwareRequestFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityContextHolderAwareRequestFilterTests {
    Mockery jmock = new JUnit4Mockery();

    //~ Methods ========================================================================================================

    @Test
    public void expectedRequestWrapperClassIsUsed() throws Exception {
        SecurityContextHolderAwareRequestFilter filter = new SecurityContextHolderAwareRequestFilter();
        filter.setPortResolver(new PortResolverImpl());
        filter.setWrapperClass(SavedRequestAwareWrapper.class);
        filter.setRolePrefix("ROLE_");
        filter.init(jmock.mock(FilterConfig.class));
        final FilterChain filterChain = jmock.mock(FilterChain.class);

        jmock.checking(new Expectations() {{
            exactly(2).of(filterChain).doFilter(
                    with(aNonNull(SavedRequestAwareWrapper.class)), with(aNonNull(HttpServletResponse.class)));
        }});

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), filterChain);

        // Now re-execute the filter, ensuring our replacement wrapper is still used
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), filterChain);

        filter.destroy();
    }
}

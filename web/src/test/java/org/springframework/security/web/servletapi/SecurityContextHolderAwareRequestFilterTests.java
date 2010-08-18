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

package org.springframework.security.web.servletapi;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link SecurityContextHolderAwareRequestFilter}.
 *
 * @author Ben Alex
 */
public class SecurityContextHolderAwareRequestFilterTests {

    //~ Methods ========================================================================================================

    @Test
    public void expectedRequestWrapperClassIsUsed() throws Exception {
        SecurityContextHolderAwareRequestFilter filter = new SecurityContextHolderAwareRequestFilter();
        filter.setRolePrefix("ROLE_");
        final FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), filterChain);

        // Now re-execute the filter, ensuring our replacement wrapper is still used
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), filterChain);

        verify(filterChain, times(2)).doFilter(any(SecurityContextHolderAwareRequestWrapper.class), any(HttpServletResponse.class));

        filter.destroy();
    }
}

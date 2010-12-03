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

package org.springframework.security.core.authority;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.*;
import org.springframework.security.core.GrantedAuthority;


/**
 * Tests {@link SimpleGrantedAuthority}.
 *
 * @author Ben Alex
 */
public class SimpleGrantedAuthorityTests {

    @Test
    public void equalsBehavesAsExpected() throws Exception {
        SimpleGrantedAuthority auth1 = new SimpleGrantedAuthority("TEST");
        assertEquals(auth1, auth1);
        assertEquals(auth1, new SimpleGrantedAuthority("TEST"));

        assertFalse(auth1.equals("TEST"));

        SimpleGrantedAuthority auth3 = new SimpleGrantedAuthority("NOT_EQUAL");
        assertTrue(!auth1.equals(auth3));

        assertFalse(auth1.equals(mock(GrantedAuthority.class)));

        assertFalse(auth1.equals(Integer.valueOf(222)));
    }

    @Test
    public void toStringReturnsAuthorityValue() {
        SimpleGrantedAuthority auth = new SimpleGrantedAuthority("TEST");
        assertEquals("TEST", auth.toString());
    }

}

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

package org.springframework.security.authentication.dao.salt;

import static junit.framework.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Tests {@link ReflectionSaltSource}.
 *
 * @author Ben Alex
 */
public class ReflectionSaltSourceTests {
    private UserDetails user = new User("scott", "wombat", true, true, true, true,
            AuthorityUtils.createAuthorityList("HOLDER"));

    //~ Methods ========================================================================================================

    @Test(expected=IllegalArgumentException.class)
    public void detectsMissingUserPropertyToUse() throws Exception {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.afterPropertiesSet();
    }

    @Test(expected=AuthenticationServiceException.class)
    public void exceptionIsThrownWhenInvalidPropertyRequested() throws Exception {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse("getDoesNotExist");
        saltSource.afterPropertiesSet();
        saltSource.getSalt(user);
    }

    @Test
    public void methodNameAsPropertyToUseReturnsCorrectSaltValue() {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse("getUsername");

        assertEquals("scott", saltSource.getSalt(user));
    }

    @Test
    public void propertyNameAsPropertyToUseReturnsCorrectSaltValue() {
        ReflectionSaltSource saltSource = new ReflectionSaltSource();
        saltSource.setUserPropertyToUse("password");
        assertEquals("wombat", saltSource.getSalt(user));
    }
}

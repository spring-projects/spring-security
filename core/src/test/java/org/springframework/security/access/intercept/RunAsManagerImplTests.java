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

package org.springframework.security.access.intercept;

import junit.framework.TestCase;

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.RunAsManagerImpl;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthorityUtils;


/**
 * Tests {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsManagerImplTests extends TestCase {
    public void testAlwaysSupportsClass() {
        RunAsManagerImpl runAs = new RunAsManagerImpl();
        assertTrue(runAs.supports(String.class));
    }

    public void testDoesNotReturnAdditionalAuthoritiesIfCalledWithoutARunAsSetting() throws Exception {
        UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));

        RunAsManagerImpl runAs = new RunAsManagerImpl();
        runAs.setKey("my_password");

        Authentication resultingToken = runAs.buildRunAs(inputToken, new Object(), SecurityConfig.createList("SOMETHING_WE_IGNORE"));
        assertEquals(null, resultingToken);
    }

    public void testRespectsRolePrefix() throws Exception {
        UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ONE", "TWO"));

        RunAsManagerImpl runAs = new RunAsManagerImpl();
        runAs.setKey("my_password");
        runAs.setRolePrefix("FOOBAR_");

        Authentication resultingToken = runAs.buildRunAs(inputToken, new Object(), SecurityConfig.createList("RUN_AS_SOMETHING"));

        assertTrue("Should have returned a RunAsUserToken", resultingToken instanceof RunAsUserToken);
        assertEquals(inputToken.getPrincipal(), resultingToken.getPrincipal());
        assertEquals(inputToken.getCredentials(), resultingToken.getCredentials());
        assertEquals("FOOBAR_RUN_AS_SOMETHING", resultingToken.getAuthorities().get(0).getAuthority());
        assertEquals("ONE", resultingToken.getAuthorities().get(1).getAuthority());
        assertEquals("TWO", resultingToken.getAuthorities().get(2).getAuthority());

        RunAsUserToken resultCast = (RunAsUserToken) resultingToken;
        assertEquals("my_password".hashCode(), resultCast.getKeyHash());
    }

    public void testReturnsAdditionalGrantedAuthorities() throws Exception {
        UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));

        RunAsManagerImpl runAs = new RunAsManagerImpl();
        runAs.setKey("my_password");

        Authentication resultingToken = runAs.buildRunAs(inputToken, new Object(), SecurityConfig.createList("RUN_AS_SOMETHING"));

        if (!(resultingToken instanceof RunAsUserToken)) {
            fail("Should have returned a RunAsUserToken");
        }

        assertEquals(inputToken.getPrincipal(), resultingToken.getPrincipal());
        assertEquals(inputToken.getCredentials(), resultingToken.getCredentials());
        assertEquals("ROLE_RUN_AS_SOMETHING", resultingToken.getAuthorities().get(0).getAuthority());
        assertEquals("ROLE_ONE", resultingToken.getAuthorities().get(1).getAuthority());
        assertEquals("ROLE_TWO", resultingToken.getAuthorities().get(2).getAuthority());

        RunAsUserToken resultCast = (RunAsUserToken) resultingToken;
        assertEquals("my_password".hashCode(), resultCast.getKeyHash());
    }

    public void testStartupDetectsMissingKey() throws Exception {
        RunAsManagerImpl runAs = new RunAsManagerImpl();

        try {
            runAs.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupSuccessfulWithKey() throws Exception {
        RunAsManagerImpl runAs = new RunAsManagerImpl();
        runAs.setKey("hello_world");
        runAs.afterPropertiesSet();
        assertEquals("hello_world", runAs.getKey());
    }

    public void testSupports() throws Exception {
        RunAsManager runAs = new RunAsManagerImpl();
        assertTrue(runAs.supports(new SecurityConfig("RUN_AS_SOMETHING")));
        assertTrue(!runAs.supports(new SecurityConfig("ROLE_WHICH_IS_IGNORED")));
        assertTrue(!runAs.supports(new SecurityConfig("role_LOWER_CASE_FAILS")));
    }
}

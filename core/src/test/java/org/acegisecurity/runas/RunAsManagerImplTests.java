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

package net.sf.acegisecurity.runas;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.RunAsManager;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsManagerImplTests extends TestCase {
    //~ Constructors ===========================================================

    public RunAsManagerImplTests() {
        super();
    }

    public RunAsManagerImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RunAsManagerImplTests.class);
    }

    public void testAlwaysSupportsClass() {
        RunAsManagerImpl runAs = new RunAsManagerImpl();
        assertTrue(runAs.supports(String.class));
    }

    public void testDoesNotReturnAdditionalAuthoritiesIfCalledWithoutARunAsSetting()
        throws Exception {
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("SOMETHING_WE_IGNORE"));

        UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        RunAsManagerImpl runAs = new RunAsManagerImpl();
        runAs.setKey("my_password");

        Authentication resultingToken = runAs.buildRunAs(inputToken,
                new Object(), def);
        assertEquals(null, resultingToken);
    }

    public void testReturnsAdditionalGrantedAuthorities()
        throws Exception {
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("RUN_AS_SOMETHING"));

        UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        RunAsManagerImpl runAs = new RunAsManagerImpl();
        runAs.setKey("my_password");

        Authentication resultingToken = runAs.buildRunAs(inputToken,
                new Object(), def);

        if (!(resultingToken instanceof RunAsUserToken)) {
            fail("Should have returned a RunAsUserToken");
        }

        assertEquals(inputToken.getPrincipal(), resultingToken.getPrincipal());
        assertEquals(inputToken.getCredentials(),
            resultingToken.getCredentials());
        assertEquals("ROLE_RUN_AS_SOMETHING",
            resultingToken.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_ONE",
            resultingToken.getAuthorities()[1].getAuthority());
        assertEquals("ROLE_TWO",
            resultingToken.getAuthorities()[2].getAuthority());

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

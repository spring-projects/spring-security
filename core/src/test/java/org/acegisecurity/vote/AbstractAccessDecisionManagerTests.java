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

package net.sf.acegisecurity.vote;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.SecurityConfig;

import org.aopalliance.intercept.MethodInvocation;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link AbstractAccessDecisionManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractAccessDecisionManagerTests extends TestCase {
    //~ Constructors ===========================================================

    public AbstractAccessDecisionManagerTests() {
        super();
    }

    public AbstractAccessDecisionManagerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractAccessDecisionManagerTests.class);
    }

    public void testAllowIfAccessDecisionManagerDefaults()
        throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        assertTrue(!mock.isAllowIfAllAbstainDecisions()); // default
        mock.setAllowIfAllAbstainDecisions(true);
        assertTrue(mock.isAllowIfAllAbstainDecisions()); // changed
    }

    public void testDelegatesSupportsRequests() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        DenyVoter voter = new DenyVoter();
        DenyAgainVoter denyVoter = new DenyAgainVoter();
        list.add(voter);
        list.add(denyVoter);
        mock.setDecisionVoters(list);

        ConfigAttribute attr = new SecurityConfig("DENY_AGAIN_FOR_SURE");
        assertTrue(mock.supports(attr));

        ConfigAttribute badAttr = new SecurityConfig("WE_DONT_SUPPORT_THIS");
        assertTrue(!mock.supports(badAttr));
    }

    public void testProperlyStoresListOfVoters() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        DenyVoter voter = new DenyVoter();
        DenyAgainVoter denyVoter = new DenyAgainVoter();
        list.add(voter);
        list.add(denyVoter);
        mock.setDecisionVoters(list);
        assertEquals(list.size(), mock.getDecisionVoters().size());
    }

    public void testRejectsEmptyList() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();

        try {
            mock.setDecisionVoters(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsListContainingInvalidObjectTypes()
        throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        DenyVoter voter = new DenyVoter();
        DenyAgainVoter denyVoter = new DenyAgainVoter();
        String notAVoter = "NOT_A_VOTER";
        list.add(voter);
        list.add(notAVoter);
        list.add(denyVoter);

        try {
            mock.setDecisionVoters(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullVotersList() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();

        try {
            mock.setDecisionVoters(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testWillNotStartIfDecisionVotersNotSet()
        throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();

        try {
            mock.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    //~ Inner Classes ==========================================================

    private class MockDecisionManagerImpl extends AbstractAccessDecisionManager {
        public void decide(Authentication authentication,
            MethodInvocation invocation, ConfigAttributeDefinition config)
            throws AccessDeniedException {
            return;
        }
    }
}

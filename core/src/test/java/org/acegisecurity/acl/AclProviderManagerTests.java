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

package net.sf.acegisecurity.acl;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.acl.basic.NamedEntityObjectIdentity;
import net.sf.acegisecurity.acl.basic.SimpleAclEntry;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link AclProviderManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclProviderManagerTests extends TestCase {
    //~ Constructors ===========================================================

    public AclProviderManagerTests() {
        super();
    }

    public AclProviderManagerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AclProviderManagerTests.class);
    }

    public void testAclLookupFails() {
        AclProviderManager mgr = makeProviderManager();
        assertNull(mgr.getAcls(new Integer(5)));
    }

    public void testAclLookupForGivenAuthenticationSuccess() {
        AclProviderManager mgr = makeProviderManager();
        assertNotNull(mgr.getAcls("STRING",
                new UsernamePasswordAuthenticationToken("marissa", "not used")));
    }

    public void testAclLookupSuccess() {
        AclProviderManager mgr = makeProviderManager();
        assertNotNull(mgr.getAcls("STRING"));
    }

    public void testRejectsNulls() {
        AclProviderManager mgr = new AclProviderManager();

        try {
            mgr.getAcls(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            mgr.getAcls(null,
                new UsernamePasswordAuthenticationToken("marissa", "not used"));
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            mgr.getAcls("SOME_DOMAIN_INSTANCE", null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testReturnsNullIfNoSupportingProvider() {
        AclProviderManager mgr = makeProviderManager();
        assertNull(mgr.getAcls(new Integer(4),
                new UsernamePasswordAuthenticationToken("marissa", "not used")));
        assertNull(mgr.getAcls(new Integer(4)));
    }

    public void testStartupFailsIfProviderListNotContainingProviders()
        throws Exception {
        List providers = new Vector();
        providers.add("THIS_IS_NOT_A_PROVIDER");

        AclProviderManager mgr = new AclProviderManager();

        try {
            mgr.setProviders(providers);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfProviderListNotSet()
        throws Exception {
        AclProviderManager mgr = new AclProviderManager();

        try {
            mgr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfProviderListNull() throws Exception {
        AclProviderManager mgr = new AclProviderManager();

        try {
            mgr.setProviders(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSuccessfulStartup() throws Exception {
        AclProviderManager mgr = makeProviderManager();
        mgr.afterPropertiesSet();
        assertTrue(true);
        assertEquals(1, mgr.getProviders().size());
    }

    private AclProviderManager makeProviderManager() {
        MockProvider provider1 = new MockProvider();
        List providers = new Vector();
        providers.add(provider1);

        AclProviderManager mgr = new AclProviderManager();
        mgr.setProviders(providers);

        return mgr;
    }

    //~ Inner Classes ==========================================================

    private class MockProvider implements AclProvider {
        private UsernamePasswordAuthenticationToken marissa = new UsernamePasswordAuthenticationToken("marissa",
                "not used",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FOO"), new GrantedAuthorityImpl("ROLE_BAR")});
        private SimpleAclEntry entry100Marissa = new SimpleAclEntry(marissa
                .getPrincipal(),
                new NamedEntityObjectIdentity("OBJECT", "100"), null, 2);
        private UsernamePasswordAuthenticationToken scott = new UsernamePasswordAuthenticationToken("scott",
                "not used",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FOO"), new GrantedAuthorityImpl("ROLE_MANAGER")});
        private SimpleAclEntry entry100Scott = new SimpleAclEntry(scott
                .getPrincipal(),
                new NamedEntityObjectIdentity("OBJECT", "100"), null, 4);

        public AclEntry[] getAcls(Object domainInstance,
            Authentication authentication) {
            if (authentication.getPrincipal().equals(scott.getPrincipal())) {
                return new AclEntry[] {entry100Scott};
            }

            if (authentication.getPrincipal().equals(marissa.getPrincipal())) {
                return new AclEntry[] {entry100Marissa};
            }

            return null;
        }

        public AclEntry[] getAcls(Object domainInstance) {
            return new AclEntry[] {entry100Marissa, entry100Scott};
        }

        /**
         * Only supports <code>Object</code>s of type <code>String</code>
         *
         * @param domainInstance DOCUMENT ME!
         *
         * @return DOCUMENT ME!
         */
        public boolean supports(Object domainInstance) {
            return (domainInstance instanceof String);
        }
    }
}

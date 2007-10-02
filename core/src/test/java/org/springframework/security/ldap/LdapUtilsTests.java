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

package org.springframework.security.ldap;

import org.jmock.Mock;
import org.jmock.MockObjectTestCase;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;


/**
 * Tests {@link LdapUtils}
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUtilsTests extends MockObjectTestCase {

    //~ Methods ========================================================================================================

    public void testCloseContextSwallowsNamingException() {
        Mock mockCtx = mock(DirContext.class);

        mockCtx.expects(once()).method("close").will(throwException(new NamingException()));

        LdapUtils.closeContext((Context) mockCtx.proxy());
    }

    public void testGetRelativeNameReturnsEmptyStringForDnEqualToBaseName()
        throws Exception {
        Mock mockCtx = mock(DirContext.class);

        mockCtx.expects(atLeastOnce()).method("getNameInNamespace").will(returnValue("dc=springframework,dc=org"));

        assertEquals("", LdapUtils.getRelativeName("dc=springframework,dc=org", (Context) mockCtx.proxy()));
    }

    public void testGetRelativeNameReturnsFullDnWithEmptyBaseName()
        throws Exception {
        Mock mockCtx = mock(DirContext.class);

        mockCtx.expects(atLeastOnce()).method("getNameInNamespace").will(returnValue(""));

        assertEquals("cn=jane,dc=springframework,dc=org",
            LdapUtils.getRelativeName("cn=jane,dc=springframework,dc=org", (Context) mockCtx.proxy()));
    }

    public void testGetRelativeNameWorksWithArbitrarySpaces()
        throws Exception {
        Mock mockCtx = mock(DirContext.class);

        mockCtx.expects(atLeastOnce()).method("getNameInNamespace").will(returnValue("dc=acegisecurity,dc = org"));

        assertEquals("cn=jane smith",
            LdapUtils.getRelativeName("cn=jane smith, dc = acegisecurity , dc=org", (Context) mockCtx.proxy()));
    }

    public void testRootDnsAreParsedFromUrlsCorrectly() {
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine"));
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine/"));
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine.co.uk/"));
        assertEquals("dc=springframework,dc=org",
            LdapUtils.parseRootDnFromUrl("ldaps://monkeymachine.co.uk/dc=springframework,dc=org"));
        assertEquals("dc=springframework,dc=org", LdapUtils.parseRootDnFromUrl("ldap:///dc=springframework,dc=org"));
        assertEquals("dc=springframework,dc=org",
            LdapUtils.parseRootDnFromUrl("ldap://monkeymachine/dc=springframework,dc=org"));
        assertEquals("dc=springframework,dc=org/ou=blah",
            LdapUtils.parseRootDnFromUrl("ldap://monkeymachine.co.uk/dc=springframework,dc=org/ou=blah"));
    }
}

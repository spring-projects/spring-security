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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.junit.Test;


/**
 * Tests {@link LdapUtils}
 *
 * @author Luke Taylor
 */
public class LdapUtilsTests {

    //~ Methods ========================================================================================================

    @Test
    public void testCloseContextSwallowsNamingException() throws Exception {
        final DirContext dirCtx = mock(DirContext.class);
        doThrow(new NamingException()).when(dirCtx).close();

        LdapUtils.closeContext(dirCtx);
    }

    @Test
    public void testGetRelativeNameReturnsEmptyStringForDnEqualToBaseName() throws Exception {
        final DirContext mockCtx = mock(DirContext.class);

        when(mockCtx.getNameInNamespace()).thenReturn("dc=springframework,dc=org");

        assertEquals("", LdapUtils.getRelativeName("dc=springframework,dc=org", mockCtx));
    }

    @Test
    public void testGetRelativeNameReturnsFullDnWithEmptyBaseName() throws Exception {
        final DirContext mockCtx = mock(DirContext.class);
        when(mockCtx.getNameInNamespace()).thenReturn("");

        assertEquals("cn=jane,dc=springframework,dc=org",
            LdapUtils.getRelativeName("cn=jane,dc=springframework,dc=org", mockCtx));
    }

    @Test
    public void testGetRelativeNameWorksWithArbitrarySpaces() throws Exception {
        final DirContext mockCtx = mock(DirContext.class);
        when(mockCtx.getNameInNamespace()).thenReturn("dc=springsecurity,dc = org");

        assertEquals("cn=jane smith",
            LdapUtils.getRelativeName("cn=jane smith, dc = springsecurity , dc=org", mockCtx));
    }

    @Test
    public void testRootDnsAreParsedFromUrlsCorrectly() {
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine"));
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine:11389"));
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine/"));
        assertEquals("", LdapUtils.parseRootDnFromUrl("ldap://monkeymachine.co.uk/"));
        assertEquals("dc=springframework,dc=org",
            LdapUtils.parseRootDnFromUrl("ldaps://monkeymachine.co.uk/dc=springframework,dc=org"));
        assertEquals("dc=springframework,dc=org", LdapUtils.parseRootDnFromUrl("ldap:///dc=springframework,dc=org"));
        assertEquals("dc=springframework,dc=org",
            LdapUtils.parseRootDnFromUrl("ldap://monkeymachine/dc=springframework,dc=org"));
        assertEquals("dc=springframework,dc=org/ou=blah",
            LdapUtils.parseRootDnFromUrl("ldap://monkeymachine.co.uk/dc=springframework,dc=org/ou=blah"));
        assertEquals("dc=springframework,dc=org/ou=blah",
            LdapUtils.parseRootDnFromUrl("ldap://monkeymachine.co.uk:389/dc=springframework,dc=org/ou=blah"));
    }
}

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

package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.MockInitialDirContextFactory;

import org.jmock.Mock;
import org.jmock.MockObjectTestCase;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;


/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordComparisonAuthenticatorMockTests extends MockObjectTestCase {
    //~ Methods ========================================================================================================

    public void testLdapCompareIsUsedWhenPasswordIsNotRetrieved()
        throws Exception {
        Mock mockCtx = mock(DirContext.class);

        PasswordComparisonAuthenticator authenticator = new PasswordComparisonAuthenticator(new MockInitialDirContextFactory(
                    (DirContext) mockCtx.proxy(), "dc=acegisecurity,dc=org"));

        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});

        // Get the mock to return an empty attribute set
        mockCtx.expects(atLeastOnce()).method("getNameInNamespace").will(returnValue("dc=acegisecurity,dc=org"));
        mockCtx.expects(once()).method("lookup").with(eq("cn=Bob, ou=people")).will(returnValue(true));
        mockCtx.expects(once()).method("getAttributes").with(eq("cn=Bob, ou=people"), NULL)
               .will(returnValue(new BasicAttributes()));

        // Setup a single return value (i.e. success)
        Attributes searchResults = new BasicAttributes("", null);
        mockCtx.expects(once())
                .method("search")
                .with(eq("cn=Bob, ou=people"), eq("(userPassword={0})"), NOT_NULL, NOT_NULL)
                .will(returnValue(searchResults.getAll()));
        mockCtx.expects(atLeastOnce()).method("close");
        authenticator.authenticate("Bob", "bobspassword");
    }
}

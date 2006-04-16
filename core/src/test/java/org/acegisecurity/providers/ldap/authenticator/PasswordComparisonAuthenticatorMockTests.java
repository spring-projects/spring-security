package org.acegisecurity.providers.ldap.authenticator;

import org.jmock.Mock;
import org.jmock.MockObjectTestCase;
import org.acegisecurity.ldap.InitialDirContextFactory;

import javax.naming.directory.DirContext;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.Attributes;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordComparisonAuthenticatorMockTests extends MockObjectTestCase {

    public void testLdapCompareIsUsedWhenPasswordIsNotRetrieved() throws Exception {
        Mock mockCtx = mock(DirContext.class);

        PasswordComparisonAuthenticator authenticator =
                new PasswordComparisonAuthenticator(new MockInitialDirContextFactory(
                        (DirContext)mockCtx.proxy(),
                        "dc=acegisecurity,dc=org")
                );

        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});

        // Get the mock to return an empty attribute set
        mockCtx.expects(atLeastOnce()).method("getNameInNamespace").will(returnValue("dc=acegisecurity,dc=org"));
        mockCtx.expects(once()).method("getAttributes").with(eq("cn=Bob,ou=people"), NULL).will(returnValue(new BasicAttributes()));
        // Setup a single return value (i.e. success)
        Attributes searchResults = new BasicAttributes("", null);
        mockCtx.expects(once()).method("search").with(eq("cn=Bob,ou=people"),
                eq("(userPassword={0})"), NOT_NULL, NOT_NULL).will(returnValue(searchResults.getAll()));
        mockCtx.expects(once()).method("close");
        authenticator.authenticate("Bob", "bobspassword");
    }

    class MockInitialDirContextFactory implements InitialDirContextFactory {
        DirContext ctx;
        String baseDn;

        public MockInitialDirContextFactory(DirContext ctx, String baseDn) {
            this.baseDn = baseDn;
            this.ctx = ctx;
        }

        public DirContext newInitialDirContext() {
            return ctx;
        }

        public DirContext newInitialDirContext(String username, String password) {
            return ctx;
        }

        public String getRootDn() {
            return baseDn;
        }
    }
}

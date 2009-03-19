package org.springframework.security.ldap;

import static org.junit.Assert.*;

import java.util.Hashtable;

import org.junit.Test;
import org.springframework.ldap.core.support.AbstractContextSource;


/**
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultSpringSecurityContextSourceTests {

    @Test
    public void instantiationSucceedsWithExpectedProperties() {
        DefaultSpringSecurityContextSource ctxSrc =
            new DefaultSpringSecurityContextSource("ldap://blah:789/dc=springframework,dc=org");
        assertFalse(ctxSrc.isAnonymousReadOnly());
        assertTrue(ctxSrc.isPooled());
    }

    @Test
    public void supportsSpacesInUrl() {
        new DefaultSpringSecurityContextSource("ldap://myhost:10389/dc=spring%20framework,dc=org");
    }

    @Test
    public void poolingFlagIsSetWhenAuthenticationDnMatchesManagerUserDn() throws Exception {
        EnvExposingDefaultSpringSecurityContextSource ctxSrc =
            new EnvExposingDefaultSpringSecurityContextSource("ldap://blah:789/dc=springframework,dc=org");
        ctxSrc.setUserDn("manager");
        ctxSrc.setPassword("password");
        ctxSrc.afterPropertiesSet();
        assertTrue(ctxSrc.getAuthenticatedEnvForTest("manager", "password").containsKey(AbstractContextSource.SUN_LDAP_POOLING_FLAG));
    }

    @Test
    public void poolingFlagIsNotSetWhenAuthenticationDnIsNotManagerUserDn() throws Exception {
        EnvExposingDefaultSpringSecurityContextSource ctxSrc =
            new EnvExposingDefaultSpringSecurityContextSource("ldap://blah:789/dc=springframework,dc=org");
        ctxSrc.setUserDn("manager");
        ctxSrc.setPassword("password");
        ctxSrc.afterPropertiesSet();
        assertFalse(ctxSrc.getAuthenticatedEnvForTest("user", "password").containsKey(AbstractContextSource.SUN_LDAP_POOLING_FLAG));
    }

    static class EnvExposingDefaultSpringSecurityContextSource extends DefaultSpringSecurityContextSource {
        public EnvExposingDefaultSpringSecurityContextSource(String providerUrl) {
            super(providerUrl);
        }

        @SuppressWarnings("unchecked")
        Hashtable getAuthenticatedEnvForTest(String userDn, String password) {
            return getAuthenticatedEnv(userDn, password);
        }
    }
}

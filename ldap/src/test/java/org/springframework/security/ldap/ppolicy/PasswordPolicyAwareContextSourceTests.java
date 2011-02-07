package org.springframework.security.ldap.ppolicy;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.*;

import org.junit.*;
import org.springframework.ldap.UncategorizedLdapException;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import java.util.*;

/**
 * @author Luke Taylor
 */
public class PasswordPolicyAwareContextSourceTests {
    private PasswordPolicyAwareContextSource ctxSource;
    private final LdapContext ctx = mock(LdapContext.class);

    @Before
    public void setUp() throws Exception {
        reset(ctx);
        ctxSource = new PasswordPolicyAwareContextSource("ldap://blah:789/dc=springframework,dc=org") {
            @Override
            protected DirContext createContext(Hashtable env) {
                if ("manager".equals(env.get(Context.SECURITY_PRINCIPAL))) {
                    return ctx;
                }

                return null;
            }
        };
        ctxSource.setUserDn("manager");
        ctxSource.setPassword("password");
        ctxSource.afterPropertiesSet();
    }

    @Test
    public void contextIsReturnedWhenNoControlsAreSetAndReconnectIsSuccessful() throws Exception {
        assertNotNull(ctxSource.getContext("user", "ignored"));
    }

    @Test(expected=UncategorizedLdapException.class)
    public void standardExceptionIsPropagatedWhenExceptionRaisedAndNoControlsAreSet() throws Exception {
        doThrow(new NamingException("some LDAP exception")).when(ctx).reconnect(any(Control[].class));

        ctxSource.getContext("user", "ignored");
    }

    @Test(expected=PasswordPolicyException.class)
    public void lockedPasswordPolicyControlRaisesPasswordPolicyException() throws Exception {
        when(ctx.getResponseControls()).thenReturn(new Control[] {
                new PasswordPolicyResponseControl(PasswordPolicyResponseControlTests.OPENLDAP_LOCKED_CTRL) });

        doThrow(new NamingException("locked message")).when(ctx).reconnect(any(Control[].class));

        ctxSource.getContext("user", "ignored");
    }
}

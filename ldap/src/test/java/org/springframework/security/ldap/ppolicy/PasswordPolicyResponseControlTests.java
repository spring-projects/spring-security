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

package org.springframework.security.ldap.ppolicy;

import static org.junit.Assert.*;

import org.junit.Test;

import javax.naming.ldap.Control;
import java.util.*;

/**
 * Tests for <tt>PasswordPolicyResponse</tt>.
 *
 * @author Luke Taylor
 */
public class PasswordPolicyResponseControlTests {
    //~ Methods ========================================================================================================

    /**
     * Useful method for obtaining data from a server for use in tests
     */
//    public void testAgainstServer() throws Exception {
//        Hashtable env = new Hashtable();
//        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
//        env.put(Context.PROVIDER_URL, "ldap://gorille:389/");
//        env.put(Context.SECURITY_AUTHENTICATION, "simple");
//        env.put(Context.SECURITY_PRINCIPAL, "cn=manager,dc=security,dc=org");
//        env.put(Context.SECURITY_CREDENTIALS, "security");
//        env.put(LdapContext.CONTROL_FACTORIES, PasswordPolicyControlFactory.class.getName());
//
//        InitialLdapContext ctx = new InitialLdapContext(env, null);
//
//        Control[] rctls = { new PasswordPolicyControl(false) };
//
//        ctx.setRequestControls(rctls);
//
//        try {
//            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, "uid=bob,ou=people,dc=security,dc=org" );
//            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, "bobspassword");
//            Object o = ctx.lookup("");
//
//            System.out.println(o);
//
//        } catch(NamingException ne) {
//            // Ok.
//            System.err.println(ne);
//        }
//
//        PasswordPolicyResponseControl ctrl = getPPolicyResponseCtl(ctx);
//        System.out.println(ctrl);
//
//        assertNotNull(ctrl);
//
//        //com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
//    }


//    private PasswordPolicyResponseControl getPPolicyResponseCtl(InitialLdapContext ctx) throws NamingException {
//        Control[] ctrls = ctx.getResponseControls();
//
//        for (int i = 0; ctrls != null && i < ctrls.length; i++) {
//            if (ctrls[i] instanceof PasswordPolicyResponseControl) {
//                return (PasswordPolicyResponseControl) ctrls[i];
//            }
//        }
//
//        return null;
//    }

    @Test
    public void openLDAP33SecondsTillPasswordExpiryCtrlIsParsedCorrectly() {
        byte[] ctrlBytes = {0x30, 0x05, (byte) 0xA0, 0x03, (byte) 0xA0, 0x1, 0x21};

        PasswordPolicyResponseControl ctrl = new PasswordPolicyResponseControl(ctrlBytes);

        assertTrue(ctrl.hasWarning());
        assertEquals(33, ctrl.getTimeBeforeExpiration());
    }

    @Test
    public void openLDAP496GraceLoginsRemainingCtrlIsParsedCorrectly() {
        byte[] ctrlBytes = {0x30, 0x06, (byte) 0xA0, 0x04, (byte) 0xA1, 0x02, 0x01, (byte) 0xF0};

        PasswordPolicyResponseControl ctrl = new PasswordPolicyResponseControl(ctrlBytes);

        assertTrue(ctrl.hasWarning());
        assertEquals(496, ctrl.getGraceLoginsRemaining());
    }

    static final byte[] OPENLDAP_5_LOGINS_REMAINING_CTRL = {0x30, 0x05, (byte) 0xA0, 0x03, (byte) 0xA1, 0x01, 0x05};

    @Test
    public void openLDAP5GraceLoginsRemainingCtrlIsParsedCorrectly() {
        PasswordPolicyResponseControl ctrl = new PasswordPolicyResponseControl(OPENLDAP_5_LOGINS_REMAINING_CTRL);

        assertTrue(ctrl.hasWarning());
        assertEquals(5, ctrl.getGraceLoginsRemaining());
    }

    static final byte[] OPENLDAP_LOCKED_CTRL = {0x30, 0x03, (byte) 0xA1, 0x01, 0x01};

    @Test
    public void openLDAPAccountLockedCtrlIsParsedCorrectly() {
        PasswordPolicyResponseControl ctrl = new PasswordPolicyResponseControl(OPENLDAP_LOCKED_CTRL);

        assertTrue(ctrl.hasError() && ctrl.isLocked());
        assertFalse(ctrl.hasWarning());
    }

    @Test
    public void openLDAPPasswordExpiredCtrlIsParsedCorrectly() {
        byte[] ctrlBytes = {0x30, 0x03, (byte) 0xA1, 0x01, 0x00};

        PasswordPolicyResponseControl ctrl = new PasswordPolicyResponseControl(ctrlBytes);

        assertTrue(ctrl.hasError() && ctrl.isExpired());
        assertFalse(ctrl.hasWarning());
    }
}

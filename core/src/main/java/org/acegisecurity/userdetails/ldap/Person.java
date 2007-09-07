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
package org.acegisecurity.userdetails.ldap;

import org.springframework.ldap.support.DirContextOperations;
import org.springframework.ldap.support.DirContextAdapter;
import org.springframework.util.Assert;
import org.acegisecurity.ldap.LdapUtils;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * UserDetails implementation whose properties are based on the LDAP schema for <tt>Person</tt>.
 *
 * @author Luke
 * @since 2.0
 * @version $Id$
 */
public class Person extends LdapUserDetailsImpl {
    private String sn;
    private List cn = new ArrayList();

    protected Person() {
    }

    public String getSn() {
        return sn;
    }

    public String[] getCn() {
        return (String[]) cn.toArray(new String[cn.size()]);
    }

    protected void populateContext(DirContextAdapter adapter) {
        adapter.setAttributeValue("sn", sn);
        adapter.setAttributeValues("cn", getCn());

        if(getPassword() != null) {
            adapter.setAttributeValue("userPassword", getPassword());
        }
        adapter.setAttributeValues("objectclass", new String[] {"top", "person"});
    }

    public static class Essence extends LdapUserDetailsImpl.Essence {

        public Essence() {
        }

        public Essence(DirContextOperations ctx) {
            super(ctx);
            setCn(ctx.getStringAttributes("cn"));
            setSn(ctx.getStringAttribute("sn"));
            Object passo = ctx.getObjectAttribute("userPassword");

            if(passo != null) {
                String password = LdapUtils.convertPasswordToString(passo);
                setPassword(password);
            }
        }

        public Essence(Person copyMe) {
            super(copyMe);
            setSn(copyMe.sn);
            ((Person) instance).cn = new ArrayList(copyMe.cn);
        }

        protected LdapUserDetailsImpl createTarget() {
            return new Person();
        }

        public void setSn(String sn) {
            ((Person) instance).sn = sn;
        }

        public void setCn(String[] cn) {
            ((Person) instance).cn = Arrays.asList(cn);
        }

        public void addCn(String value) {
            ((Person) instance).cn.add(value);
        }

        public LdapUserDetails createUserDetails() {
            Person p = (Person) super.createUserDetails();
            Assert.hasLength(p.sn);
            Assert.notNull(p.cn);
            Assert.notEmpty(p.cn);
            // TODO: Check contents for null entries
            return p;
        }
    }
}








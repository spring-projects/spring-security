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
package org.springframework.security.userdetails.ldap;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;


/**
 * UserDetails implementation whose properties are based on a subset of the
 * LDAP schema for <tt>inetOrgPerson</tt>.
 *
 * <p>
 * The username will be mapped from the <tt>uid</tt> attribute by default.
 *
 * @author Luke
 * @version $Id$
 */
public class InetOrgPerson extends Person {
    private String mail;
    private String uid;
    private String employeeNumber;
    private String destinationIndicator;

    public String getMail() {
        return mail;
    }

    public String getUid() {
        return uid;
    }

    public String getEmployeeNumber() {
        return employeeNumber;
    }

    public String getDestinationIndicator() {
        return destinationIndicator;
    }

    protected void populateContext(DirContextAdapter adapter) {
        super.populateContext(adapter);
        adapter.setAttributeValue("mail", mail);
        adapter.setAttributeValue("uid", uid);
        adapter.setAttributeValue("employeeNumber", employeeNumber);
        adapter.setAttributeValue("destinationIndicator", destinationIndicator);
        adapter.setAttributeValues("objectclass", new String[] {"top", "person", "organizationalPerson", "inetOrgPerson"});
    }

    public static class Essence extends Person.Essence {
        public Essence() {
        }

        public Essence(InetOrgPerson copyMe) {
            super(copyMe);
            setMail(copyMe.getMail());
            setUid(copyMe.getUid());
            setDestinationIndicator(copyMe.getDestinationIndicator());
            setEmployeeNumber(copyMe.getEmployeeNumber());
        }

        public Essence(DirContextOperations ctx) {
            super(ctx);
            setMail(ctx.getStringAttribute("mail"));
            setUid(ctx.getStringAttribute("uid"));
            setEmployeeNumber(ctx.getStringAttribute("employeeNumber"));
            setDestinationIndicator(ctx.getStringAttribute("destinationIndicator"));
        }

        protected LdapUserDetailsImpl createTarget() {
            return new InetOrgPerson();
        }

        public void setMail(String email) {
            ((InetOrgPerson) instance).mail = email;
        }

        public void setUid(String uid) {
            ((InetOrgPerson) instance).uid = uid;

            if(instance.getUsername() == null) {
                setUsername(uid);
            }
        }

        public void setEmployeeNumber(String no) {
            ((InetOrgPerson) instance).employeeNumber = no;
        }

        public void setDestinationIndicator(String destination) {
            ((InetOrgPerson) instance).destinationIndicator = destination;
        }
    }
}

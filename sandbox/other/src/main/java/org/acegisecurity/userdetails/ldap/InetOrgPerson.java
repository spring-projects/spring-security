package org.acegisecurity.userdetails.ldap;

/**
 * @author Luke
 * @version $Id$
 */
public class InetOrgPerson extends LdapUserDetailsImpl {
    String sn;
    String cn;

    public String getSn() {
        return sn;
    }

    public String getCn() {
        return cn;
    }

    public static class Essence extends LdapUserDetailsImpl.Essence {

        public Essence() {
        }

        public Essence(InetOrgPerson copyMe) {
            super(copyMe);
        }

        LdapUserDetailsImpl createTarget() {
            return new InetOrgPerson();
        }

        public void setSn(String sn) {
            ((InetOrgPerson)instance).sn = sn;
        }

        public void setCn(String cn) {
            ((InetOrgPerson)instance).cn = cn;
        }
    }

    public static void main(String[] args) {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();

        p.setSn("Scobbie");

        InetOrgPerson immutablePerson = (InetOrgPerson)p.createUserDetails();
        System.out.println(immutablePerson.getSn());

    }
}

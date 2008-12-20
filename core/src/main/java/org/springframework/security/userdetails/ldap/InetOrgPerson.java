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
    private String carLicense;
    // Person.cn
    private String destinationIndicator;
    private String departmentNumber;
    // Person.description
    private String displayName;
    private String employeeNumber;
    private String homePhone;
    private String homePostalAddress;
    private String initials;
    private String mail;
    private String mobile;
    private String o;
    private String ou;
    private String postalAddress;
    private String postalCode;
    private String roomNumber;
    private String street;
    // Person.sn
    // Person.telephoneNumber
    private String title;
    private String uid;

    public String getUid() {
        return uid;
    }
    
    public String getMail() {
        return mail;
    }

    public String getEmployeeNumber() {
        return employeeNumber;
    }
    
    public String getInitials() {
        return initials;
    }

    public String getDestinationIndicator() {
        return destinationIndicator;
    }
    
    public String getO() {
        return o;
    }    

    public String getOu() {
        return ou;
    }

    public String getTitle() {
        return title;
    }

    public String getCarLicense() {
        return carLicense;
    }

    public String getDepartmentNumber() {
        return departmentNumber;
    }

    public String getDisplayName() {
        return displayName;
    }
    
    public String getHomePhone() {
        return homePhone;
    }
    
    public String getRoomNumber() {
        return roomNumber;
    }

    public String getHomePostalAddress() {
        return homePostalAddress;
    }

    public String getMobile() {
        return mobile;
    }

    public String getPostalAddress() {
        return postalAddress;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public String getStreet() {
        return street;
    }

    protected void populateContext(DirContextAdapter adapter) {
        super.populateContext(adapter);
        adapter.setAttributeValue("carLicense", carLicense);
        adapter.setAttributeValue("departmentNumber", departmentNumber);
        adapter.setAttributeValue("destinationIndicator", destinationIndicator);        
        adapter.setAttributeValue("displayName", displayName);
        adapter.setAttributeValue("employeeNumber", employeeNumber);
        adapter.setAttributeValue("homePhone", homePhone);
        adapter.setAttributeValue("homePostalAddress", homePostalAddress);
        adapter.setAttributeValue("initials", initials);
        adapter.setAttributeValue("mail", mail);
        adapter.setAttributeValue("mobile", mobile);
        adapter.setAttributeValue("postalAddress", postalAddress);
        adapter.setAttributeValue("postalCode", postalCode);
        adapter.setAttributeValue("ou", ou);
        adapter.setAttributeValue("o", o);
        adapter.setAttributeValue("roomNumber", roomNumber);
        adapter.setAttributeValue("street", street);
        adapter.setAttributeValue("uid", uid);
        adapter.setAttributeValues("objectclass", new String[] {"top", "person", "organizationalPerson", "inetOrgPerson"});
    }

    public static class Essence extends Person.Essence {
        public Essence() {
        }

        public Essence(InetOrgPerson copyMe) {
            super(copyMe);
            setCarLicense(copyMe.getCarLicense());
            setDepartmentNumber(copyMe.getDepartmentNumber());
            setDestinationIndicator(copyMe.getDestinationIndicator());
            setDisplayName(copyMe.getDisplayName());
            setEmployeeNumber(copyMe.getEmployeeNumber());
            setHomePhone(copyMe.getHomePhone());
            setHomePostalAddress(copyMe.getHomePostalAddress());
            setInitials(copyMe.getInitials());
            setMail(copyMe.getMail());
            setMobile(copyMe.getMobile());
            setO(copyMe.getO());
            setOu(copyMe.getOu());
            setPostalAddress(copyMe.getPostalAddress());
            setPostalCode(copyMe.getPostalCode());
            setRoomNumber(copyMe.getRoomNumber());
            setStreet(copyMe.getStreet());
            setTitle(copyMe.getTitle());
            setUid(copyMe.getUid());
        }

        public Essence(DirContextOperations ctx) {
            super(ctx);
            setCarLicense(ctx.getStringAttribute("carLicense"));
            setDepartmentNumber(ctx.getStringAttribute("departmentNumber"));
            setDestinationIndicator(ctx.getStringAttribute("destinationIndicator"));
            setDisplayName(ctx.getStringAttribute("displayName"));
            setEmployeeNumber(ctx.getStringAttribute("employeeNumber"));
            setHomePhone(ctx.getStringAttribute("homePhone"));
            setHomePostalAddress(ctx.getStringAttribute("homePostalAddress"));
            setInitials(ctx.getStringAttribute("initials"));
            setMail(ctx.getStringAttribute("mail"));
            setMobile(ctx.getStringAttribute("mobile"));
            setO(ctx.getStringAttribute("o"));
            setOu(ctx.getStringAttribute("ou"));
            setPostalAddress(ctx.getStringAttribute("postalAddress"));
            setPostalCode(ctx.getStringAttribute("postalCode"));
            setRoomNumber(ctx.getStringAttribute("roomNumber"));
            setStreet(ctx.getStringAttribute("street"));
            setTitle(ctx.getStringAttribute("title"));
            setUid(ctx.getStringAttribute("uid"));            
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
        
        public void setInitials(String initials) {
            ((InetOrgPerson) instance).initials = initials;
        }        

        public void setO(String organization) {
            ((InetOrgPerson) instance).o = organization;
        }

        public void setOu(String ou) {
            ((InetOrgPerson) instance).ou = ou;
        }
        
        public void setRoomNumber(String no) {
            ((InetOrgPerson) instance).roomNumber = no;
        }        
        
        public void setTitle(String title) {
            ((InetOrgPerson) instance).title = title;
        }
        
        public void setCarLicense(String carLicense) {
            ((InetOrgPerson) instance).carLicense = carLicense;
        }
        
        public void setDepartmentNumber(String departmentNumber) {
            ((InetOrgPerson) instance).departmentNumber = departmentNumber;
        }
        
        public void setDisplayName(String displayName) {
            ((InetOrgPerson) instance).displayName = displayName;
        }

        public void setEmployeeNumber(String no) {
            ((InetOrgPerson) instance).employeeNumber = no;
        }

        public void setDestinationIndicator(String destination) {
            ((InetOrgPerson) instance).destinationIndicator = destination;
        }
        
        public void setHomePhone(String homePhone) {
            ((InetOrgPerson) instance).homePhone = homePhone;
        }  

        public void setStreet(String street) {
            ((InetOrgPerson) instance).street = street;
        }

        public void setPostalCode(String postalCode) {
            ((InetOrgPerson) instance).postalCode = postalCode;
        }

        public void setPostalAddress(String postalAddress) {
            ((InetOrgPerson) instance).postalAddress = postalAddress;
        }

        public void setMobile(String mobile) {
            ((InetOrgPerson) instance).mobile = mobile;
        }

        public void setHomePostalAddress(String homePostalAddress) {
            ((InetOrgPerson) instance).homePostalAddress = homePostalAddress;
        }
    }
}

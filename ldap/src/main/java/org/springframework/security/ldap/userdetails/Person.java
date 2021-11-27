/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.userdetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.ldap.LdapUtils;
import org.springframework.util.Assert;

/**
 * UserDetails implementation whose properties are based on the LDAP schema for
 * <tt>Person</tt>.
 *
 * @author Luke
 * @since 2.0
 */
public class Person extends LdapUserDetailsImpl {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String givenName;

	private String sn;

	private String description;

	private String telephoneNumber;

	private List<String> cn = new ArrayList<>();

	protected Person() {
	}

	public String getGivenName() {
		return this.givenName;
	}

	public String getSn() {
		return this.sn;
	}

	public String[] getCn() {
		return this.cn.toArray(new String[0]);
	}

	public String getDescription() {
		return this.description;
	}

	public String getTelephoneNumber() {
		return this.telephoneNumber;
	}

	protected void populateContext(DirContextAdapter adapter) {
		adapter.setAttributeValue("givenName", this.givenName);
		adapter.setAttributeValue("sn", this.sn);
		adapter.setAttributeValues("cn", getCn());
		adapter.setAttributeValue("description", getDescription());
		adapter.setAttributeValue("telephoneNumber", getTelephoneNumber());
		if (getPassword() != null) {
			adapter.setAttributeValue("userPassword", getPassword());
		}
		adapter.setAttributeValues("objectclass", new String[] { "top", "person" });
	}

	public static class Essence extends LdapUserDetailsImpl.Essence {

		public Essence() {
		}

		public Essence(DirContextOperations ctx) {
			super(ctx);
			setCn(ctx.getStringAttributes("cn"));
			setGivenName(ctx.getStringAttribute("givenName"));
			setSn(ctx.getStringAttribute("sn"));
			setDescription(ctx.getStringAttribute("description"));
			setTelephoneNumber(ctx.getStringAttribute("telephoneNumber"));
			Object password = ctx.getObjectAttribute("userPassword");
			if (password != null) {
				setPassword(LdapUtils.convertPasswordToString(password));
			}
		}

		public Essence(Person copyMe) {
			super(copyMe);
			setGivenName(copyMe.givenName);
			setSn(copyMe.sn);
			setDescription(copyMe.getDescription());
			setTelephoneNumber(copyMe.getTelephoneNumber());
			((Person) this.instance).cn = new ArrayList<>(copyMe.cn);
		}

		@Override
		protected LdapUserDetailsImpl createTarget() {
			return new Person();
		}

		public void setGivenName(String givenName) {
			((Person) this.instance).givenName = givenName;
		}

		public void setSn(String sn) {
			((Person) this.instance).sn = sn;
		}

		public void setCn(String[] cn) {
			((Person) this.instance).cn = Arrays.asList(cn);
		}

		public void addCn(String value) {
			((Person) this.instance).cn.add(value);
		}

		public void setTelephoneNumber(String tel) {
			((Person) this.instance).telephoneNumber = tel;
		}

		public void setDescription(String desc) {
			((Person) this.instance).description = desc;
		}

		@Override
		public LdapUserDetails createUserDetails() {
			Person p = (Person) super.createUserDetails();
			Assert.notNull(p.cn, "person.sn cannot be null");
			Assert.notEmpty(p.cn, "person.cn cannot be empty");
			// TODO: Check contents for null entries
			return p;
		}

	}

}

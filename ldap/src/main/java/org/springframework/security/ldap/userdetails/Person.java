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

import org.jspecify.annotations.Nullable;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
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

	private static final long serialVersionUID = 620L;

	private @Nullable String givenName;

	private @Nullable String sn;

	private @Nullable String description;

	private @Nullable String telephoneNumber;

	private List<String> cn = new ArrayList<>();

	protected Person() {
	}

	public @Nullable String getGivenName() {
		return this.givenName;
	}

	public @Nullable String getSn() {
		return this.sn;
	}

	public String[] getCn() {
		return this.cn.toArray(new String[0]);
	}

	public @Nullable String getDescription() {
		return this.description;
	}

	public @Nullable String getTelephoneNumber() {
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
			String[] cns = ctx.getStringAttributes("cn");
			cns = (cns != null) ? cns : new String[0];
			setCn(cns);
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
			setCn(copyMe.cn.toArray(String[]::new));
		}

		@Override
		protected LdapUserDetailsImpl createTarget() {
			return new Person();
		}

		public void setGivenName(@Nullable String givenName) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((Person) this.instance).givenName = givenName;
		}

		public void setSn(@Nullable String sn) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((Person) this.instance).sn = sn;
		}

		public void setCn(String[] cn) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((Person) this.instance).cn = Arrays.asList(cn);
		}

		public void addCn(String value) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((Person) this.instance).cn.add(value);
		}

		public void setTelephoneNumber(@Nullable String tel) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((Person) this.instance).telephoneNumber = tel;
		}

		public void setDescription(@Nullable String desc) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
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

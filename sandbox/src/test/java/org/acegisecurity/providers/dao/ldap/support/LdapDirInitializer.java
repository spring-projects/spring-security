/* Copyright 2004, 2005 Acegi Technology Pty Limited
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
package org.acegisecurity.providers.dao.ldap.support;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

/** Container for a bunch of methods begining with 'dirInit' and taking 
 *  a JNDI DirContext, which are used to construct the initial state 
 *  of the EmbeddedServer <b>before</b> Unit tests are run.
 *  
 * @TODO Externalize this into a LDIF resource file(s); I would have done this, but 
 *   I can't seem to get this to work in both Eclipse and Maven at the same time.
 *   
 * @author robert.sanders
 *
 */
public class LdapDirInitializer {
	
	public static void intializeDir(DirContext ctx) throws NamingException {
		LdapDirInitializer ldi = new LdapDirInitializer();
		
		ldi.dirInit_SimpleUidUser(ctx);
		
		ldi.dirInit_SimpleCnUser(ctx);
		
		ldi.dirInit_OuOthers(ctx);
		
		ldi.dirInit_UserNamedOtherOne(ctx);
		
		ldi.dirInit_UserNamedOtherTwo(ctx);
	}

	private void dirInit_SimpleUidUser(DirContext ctx) throws NamingException {
		String name = "uid=one.user,ou=users";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "User One");
        attrs.put("sn", "One");
        attrs.put("givenName", "User");
        attrs.put("uid", "user.one");
        attrs.put("mail", "one.user@hotmail.com");
        attrs.put("userPassword", "plaintext");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
        
        ctx.createSubcontext(name, attrs);
	}
	
	private void dirInit_SimpleCnUser(DirContext ctx) throws NamingException {
		String name = "cn=User Two,ou=users";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "Two User");
        attrs.put("givenName", "Two");
        attrs.put("sn", "User");
        attrs.put("uid", "user.two");
        attrs.put("mail", "user.two@hotmail.com");
        attrs.put("userPassword", "plaintext2");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
        
        ctx.createSubcontext(name, attrs);
	}
	
	private void dirInit_UserNamedOtherOne(DirContext ctx) throws NamingException {
		String name = "uid=other.one,ou=others";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "Other One");
        attrs.put("givenName", "Other");
        attrs.put("sn", "One");
        attrs.put("uid", "other.one");
        attrs.put("mail", "other.one@hotmail.com");
        attrs.put("userPassword", "otherone");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
        
		ctx.createSubcontext(name, attrs);
	}
	
	private void dirInit_UserNamedOtherTwo(DirContext ctx) throws NamingException {
		String name = "uid=other.two,ou=others";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "Other Two");
        attrs.put("givenName", "Other");
        attrs.put("sn", "Two");
        attrs.put("uid", "other.two");
        attrs.put("mail", "other.two@hotmail.com");
        attrs.put("userPassword", "othertwo");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
		
		ctx.createSubcontext(name, attrs);
	}
	 
	private void dirInit_OuOthers(DirContext ctx) throws NamingException {
		String otherUserOU = "ou=Others";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", otherUserOU + ",ou=system");
        attrs.put("ou", "others");
        attrs.put("objectClass", "top");
        attrs.put("objectClass", "organizationalUnit");
        
        ctx.createSubcontext(otherUserOU, attrs);
	}
	
}

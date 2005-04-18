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

package net.sf.acegisecurity.providers.dao.ldap;

import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.PasswordAuthenticationDao;
import net.sf.acegisecurity.providers.dao.User;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;


/**
* <p>
* LdapPasswordAuthenticationDao allows you to authenticate user's against LDAP Directories via JNDI.  
* LDAP administrators have a wide variety of options available to them when configuring a server, 
* so the LdapPasswordAuthenticationDao has a wide variety of ways that it can be configured. </p>
* 
* <STYLE TYPE="text/css"><!--
* .syntax0 {
* color: #000000;
* }
* .syntax1 {
* color: #cc0000;
* }
* .syntax2 {
* color: #ff8400;
* }
* .syntax3 {
* color: #6600cc;
* }
* .syntax4 {
* color: #cc6600;
* }
* .syntax5 {
* color: #ff0000;
* }
* .syntax6 {
* color: #9966ff;
* }
* .syntax7 {
* background: #ffffcc;
* color: #ff0066;
* }
* .syntax8 {
* color: #006699;
* font-weight: bold;
* }
* .syntax9 {
* color: #009966;
* font-weight: bold;
* }
* .syntax10 {
* color: #0099ff;
* font-weight: bold;
* }
* .syntax11 {
* color: #66ccff;
* font-weight: bold;
* }
* .syntax12 {
* color: #02b902;
* }
* .syntax13 {
* color: #ff00cc;
* }
* .syntax14 {
* color: #cc00cc;
* }
* .syntax15 {
* color: #9900cc;
* }
* .syntax16 {
* color: #6600cc;
* }
* .syntax17 {
* color: #0000ff;
* }
* .syntax18 {
* color: #000000;
* font-weight: bold;
* }
* -->
* </STYLE>
* <p>
* Currently LdapPasswordAuthenticationDao authenticates a username/password pair by 
* 'logging in to' the LDAP server via a JNDI bind() operation.  
* There is some flexibility in that multiple userContexts can be set; the 
* LdapPasswordAuthenticationDao will attempt to bind() against each until either a bind() 
* operation succeeds or all  userContexts have been tried. </p>
* 
* <p>
* LdapPasswordAuthenticationDao offers 3 modes for determining the roles assigned to a user 
* (these can be used in combination). </p>
* <ul>
*     <li>The simplest method is to use the defaultRolename property.  
*         If set, and no other roles are found for an authenticated user, 
*         the value of defaultRolename is assigned as the sole role of the user. 
*     </li>
*     <li>Roles can be retrieved from the context created by the user login 
*         (the userContext against which the username/password for the user resulted in a successful bind()).  
*         The attribute names from which roles will be retrieved in this mode are specified by the 
*         userRolesAttributes property.
*     </li>
*     <li>Roles can be searched for within the LDAP directory.  
*         This option requires three properties to be set: 
*         the roleContexts property determines the context(s) which will be searched; 
*         the roleAttributesSearchFilter property specifies an LDAP search filter 
*         (with placeholders for the username and/or DN of the user); 
*         while the roleNameAttributes specifies the attributes which (may) contain role information.
*     </li>
* </ul>
* 
* <p>
* If the both the userRolesAttributes method and the roleContexts search method are used, 
* and if both return results, then the final list of roles will be determined by combining the two results.
* </p>
* <p>
* One final operation is performed before returning the list of GrantedAuthority 
* objects associated with the user: if the the upperCaseRoleNames property is set to 
* true the user's role names are capitalized; then the values of the rolePrefix and roleSuffix 
* are used to wrap any role names.
* </p>
* <p>
* At this point a few examples will probably help clear up the confusion 
* that the abstract description above may have created.  
* Unless otherwise noted, all examples will use the following base set of assumptions: 
* An LDAP server reachable at the url ldap://ldap.mycompany.com:389/ 
* and a rootContext of dc=mycompany,dc=com.  The following would be you AuthenticationProvider:
* <PRE>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">id</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">authenticationProvider</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">class</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">net.sf.acegisecurity.providers.dao.PasswordDaoAuthenticationProvider</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">passwordAuthenticationDao</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">ref</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">local</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">ldapDaoImpl</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
* </PRE>
* </p>
* 
* <p>
* First example: your users are stored under the rootContext as cn=USERNAME,ou=Users; 
* user objects have the attribute memberOf which contains the names of any roles they 
* have been granted.  You would use the following bean configuration:
* <PRE>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">id</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">ldapDaoImpl</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">class</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">net.sf.acegisecurity.providers.dao.ldap.LdapPasswordAuthenticationDao</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">url</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>ldap://ldap.mycompany.com:389/<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">rootContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">userContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">alue</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>cn={0},ou=Users,dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">userRolesAttribute</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>memberOf<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
* </PRE>
* </p>
* 
* <p>
* Second example: users are stored under the rootContext as uid=USERNAME,ou=Users; 
* user object have no role information.  Groups (aka roles) are stored as objects 
* under the context ou=Groups and have an attribute memberUid which contains the 
* full distinguished name of the user.  You would use the following bean configuration:
* <PRE>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">id</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">ldapDaoImpl</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">class</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">net.sf.acegisecurity.providers.dao.ldap.LdapPasswordAuthenticationDao</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">url</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>ldap://ldap.mycompany.com:389/<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">rootContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax1">&lt;!--</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">here</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">{0}</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">is</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">the</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">username</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">--&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">userContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>uid={0},ou=Users,dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">roleContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>ou=Groups<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax1">&lt;!--</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">here</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">{0}</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">is</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">the</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">distinguished</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">name</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">(which</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">would</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">be</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">uid=USERNAME,ou=Users,dc=mycompany,cd=com</SPAN>
*           <SPAN CLASS="syntax1">and</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">{1}</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">is</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">the</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">username.</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">--&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">roleAttributesSearchFilter</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>(memberUid={0})<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">roleNameAttribute</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>memberUid<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
* </PRE>
* </p>
* 
* <p>
* Third example: under the rootContext your users are stored as uid=USERNAME,ou=Users.
* You don't care about the roles stored in the LDAP, all you want to know is if the user 
* can login via LDAP.  You would use the following bean configuration:
* <PRE>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">id</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">ldapDaoImpl</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">class</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">net.sf.acegisecurity.providers.dao.ldap.LdapPasswordAuthenticationDao</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">url</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>ldap://ldap.mycompany.com:389/<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">rootContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">userContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">alue</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>cn={0},ou=Users,dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">defaultRolename</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>USER<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
* </PRE>
* </p>
* 
* <p>
* Forth example (something more complex): under the rootContext your users are stored in to seperate subContexts.
* Your internal users are under uid=USERNAME,ou=Users; you also have client logins stored 
* under the context uid=USERNAME,ou=Clients.  For internal users role information is stored 
* under the context ou=Groups and have an attribute memberUid which contains the 
* full distinguished name of the user.  For clients, role information is stored as an attribute 
* memberOf as part of their user object.  You could split the definitions up into two separate 
* LdapPasswordAuthenticationDao beans, but you could also use:
* <PRE>
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">id</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">ldapDaoImpl</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">class</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">net.sf.acegisecurity.providers.dao.ldap.LdapPasswordAuthenticationDao</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">url</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>ldap://ldap.mycompany.com:389/<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">rootContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax1">&lt;!--</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">here</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">{0}</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">is</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">the</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">username</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">--&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">userContexts</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*           <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">list</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*             <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>uid={0},ou=Users,dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*             <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>uid={0},ou=Clients,dc=mycompany,dc=com<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*           <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">list</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">userRolesAttribute</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>memberOf<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">roleContext</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>ou=Groups<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax1">&lt;!--</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">here</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">{0}</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">is</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">the</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">distinguished</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">name</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">(which</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">would</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">be</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">uid=USERNAME,ou=Users,dc=mycompany,cd=com</SPAN>
*           <SPAN CLASS="syntax1">and</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">{1}</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">is</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">the</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">username.</SPAN><SPAN CLASS="syntax1"> </SPAN><SPAN CLASS="syntax1">--&gt;</SPAN>
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">roleAttributesSearchFilter</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>(memberUid={0})<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*         <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17"> </SPAN><SPAN CLASS="syntax17">name</SPAN><SPAN CLASS="syntax17">=</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax13">roleNameAttributes</SPAN><SPAN CLASS="syntax13">&quot;</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>memberUid<SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">value</SPAN><SPAN CLASS="syntax17">&gt;</SPAN><SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">property</SPAN><SPAN CLASS="syntax17">&gt;</SPAN> 
*     <SPAN CLASS="syntax17">&lt;</SPAN><SPAN CLASS="syntax17">/</SPAN><SPAN CLASS="syntax17">bean</SPAN><SPAN CLASS="syntax17">&gt;</SPAN>
* </PRE>
* </p>
*
* @author Karel Miarka
* @author Daniel Miller
* @author Robert Sanders
*/
public class LdapPasswordAuthenticationDao implements PasswordAuthenticationDao {
  
   /** InnerClass used to keep context variable together. */
   private class UserContext {
       public DirContext dirContext;
       public String userPrincipal;
       
       /**
        * Get the attribute(s) to match when searching for the user object. This
        * implementation returns a "distinguishedName" attribute with the value
        * returned by <code>getUserPrincipal(username)</code>. A subclass may
        * customize this behavior by overriding <code>getUserPrincipal</code>
        * and/or <code>getUsernameAttributes</code>.
        * 
        * @param username
        *            DOCUMENT ME!
        * 
        * @return DOCUMENT ME!
        */
       public Attributes getUsernameAttributes() {
           Attributes matchAttrs = new BasicAttributes(true); // ignore case
           matchAttrs.put(new BasicAttribute("distinguishedName", userPrincipal));
           return matchAttrs;
       }
   }
   

   public static final String BAD_CREDENTIALS_EXCEPTION_MESSAGE = "Invalid username, password or context";

   private static final transient Log log = LogFactory
           .getLog(LdapPasswordAuthenticationDao.class);

   /** Type of authentication within LDAP; default is simple. */
   private String authenticationType = "simple";

   /** If set to a non-null value, and a user can be bound to a LDAP Conext, 
    *  but no role information is found then this role is automatically added. 
    *  If null (the default) then a BadCredentialsException is thrown
    *  
    *  <p>For example; if you have an LDAP directory with no role information 
    *  stored, you might simply want to give any user who can login a role of "USER".</p>
    */
   private String defaultRole = null;

   /** The INITIAL_CONTEXT_FACTORY used to create the JNDI Factory.
    *  Default is "com.sun.jndi.ldap.LdapCtxFactory"; you <b>should not</b>
    *  need to set this unless you have unusual needs.
    **/
   private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";
   
   /** Internal variable, concatenation  */
   private String providerUrl;

   /** Used to build LDAP Search Filter for finding roles (in the roleContexts) 
    *  pointing to a user.  Uses MessageFormat like tokens; {0} is the 
    *  user's DistiguishedName, {1} is the user's username. 
    *  For more information on syntax see  
    *  javax.naming.directory.DirContext.search(), or RFC 2254. 
    *  
    *  <p>Example: if each group has an attribute 'memberUid' with values being 
    *  the usernames of the user's in that group, then the value of this property 
    *  would be <b>(memberUid={1})</b> </p> 
    **/
   private String roleAttributesSearchFilter;

   /** Contexts to search for role's (which point to the user id).
    *  <p>Example, if you have a Groups object containing Groups of users then 
    *  the expression: <b>ou=Groups,dc=mycompany,dc=com</b> might be used;
    *  alternatively, if rootContext="dc=mycompany,dc=com" then simply use "ou=Groups" here.
    **/
   private String[] roleContexts; 
   
   /** Attribute(s) of any role object returned from the roleContexts to use as role-names. 
    *  <b>Warning: </b> if you do role lookups using the roleContexts and 
    *  roleAttributesSearchFilter then you need to set roleNameAttributes or ALL attributes 
    *  will be returned.
    *  
    **/
   private String[] roleNameAttributes;  
   
   /** Prefix to be associated with any roles found for a user,
    *  defaults to an empty string.  
    *  Older versions of this class used "ROLE_" for this value. */
   private String rolePrefix = "";
   
   /** Suffix to be associated with any roles found for a user,
    *  defaults to an empty string. */
   private String roleSuffix = "";

   /** Root context of the LDAP Connection, if any is needed.  
    *  <p> Example: <b>dc=mycompany,dc=com</b> </p> 
    *  <p><strong>Note: </strong> It is usually preferable to add this data as part of the 
    *      userContexts and/or roleContexts attributes. </p> 
    **/
   private String rootContext = "";
   
   /** If true then all role name values returned from the directory 
    *  will be converted to uppercase.
    */
   private boolean upperCaseRoleNames = false;
   
   /**
    * LDAP URL (without the port) of the LDAP server to connect to; example
    * <b>ldap://dir.mycompany.com:389/</b>  (port 389 is the standard LDAP port).
    */
   private String url;
   
   /** One or more LDAP Contexts which contain user account information, use the 
    *  MessageFormat key {0} to denote location where the user's username should 
    *  be inserted into the expression to create a DistiguishedName.
    *  <p>Example: <p>cn={0},ou=Users,dc=mycompnay,dc=com</b> </p>
    *  <p>Alternatively, if you had set rootContext="dc=mycompany,dc=com" then 
    *    the first example would be rewritten as <b>cn={0},ou=Users</b>. </p>
    **/ 
   private MessageFormat[] userContexts; 

   /** Name(s) of the attribute(s) for a user account object 
    *  contaning role names assigned to the user.  Leave unset if there are none.
    *  Consult your LDAP server administrator to determine these value(s).
    *  
    **/
   private String[] userRolesAttributes;
   
   /** 
    * 
    * @param results Result of searching on of the roleContexts for matches against the current user.
    * @param roles List of roles the user has already been assigned.
    * @throws NamingException 
    */
   protected void addAnyRolesFound(NamingEnumeration results, Collection roles) throws NamingException {
       while (results.hasMore()) {
           SearchResult result = (SearchResult)results.next();
           Attributes attrs = result.getAttributes();
           if (attrs == null) {
               continue;
           }
           // Here we loop over the attributes returned in the SearchResult 
           // TODO replace with Utility method call:
           NamingEnumeration e = attrs.getAll();
           while (e.hasMore()) {
               Attribute a = (Attribute)e.next();
               for (int i = 0; i < a.size(); i++) {
                   roles.add( (String)a.get(i) );
               }
           }
       }
   }

   /**
    * @return Returns the defaultRole.
    */
   public String getDefaultRole() {
       return defaultRole;
   }

   /**
    * Get an array <code>GrantedAuthorities</code> given the list of roles
    * obtained from the LDAP context. Delegates to
    * <code>getGrantedAuthority(String ldapRole)</code>. This function may
    * be overridden in a subclass.
    * 
    * @param ldapRoles
    *            DOCUMENT ME!
    * 
    * @return DOCUMENT ME!
    */
   protected GrantedAuthority[] getGrantedAuthorities(String[] ldapRoles) {
       GrantedAuthority[] grantedAuthorities = new GrantedAuthority[ldapRoles.length];

       for (int i = 0; i < ldapRoles.length; i++) {
           grantedAuthorities[i] = getGrantedAuthority(ldapRoles[i]);
       }

       return grantedAuthorities;
   }

   /**
    * Get a <code>GrantedAuthority</code> given a role obtained from the LDAP
    * context. If found in the LDAP role, the following characters are
    * converted to underscore: ',' (comma), '=' (equals), ' ' (space) This
    * function may be overridden in a subclass.
    * 
    * @param ldapRole
    *            DOCUMENT ME!
    * 
    * @return DOCUMENT ME!
    */
   protected GrantedAuthority getGrantedAuthority(String ldapRole) {
       String roleName = rolePrefix + ldapRole.toUpperCase() + roleSuffix;
       if (upperCaseRoleNames) {
           roleName = roleName.toUpperCase();
       }
       GrantedAuthority ga = new GrantedAuthorityImpl( roleName.replaceAll("[,=\\s]", "_") );

       if (log.isDebugEnabled()) {
           log.debug("GrantedAuthority: " + ga);
       }

       return ga;
   }
   /*
   public void testGetGrantedAuthorityString() {
         LdapPasswordAuthenticationDao uut = new LdapPasswordAuthenticationDao();
         String[] test = {
                 "ROLE ABC DEF", "ROLE ABC,DEF", "ROLE ABC=DEF", "ROLE ABC_DEF",
                 "ROLE,ABC DEF", "ROLE,ABC,DEF", "ROLE,ABC=DEF", "ROLE,ABC_DEF",
                 "ROLE=ABC DEF", "ROLE=ABC,DEF", "ROLE=ABC=DEF", "ROLE=ABC_DEF",
                 "ROLE_ABC DEF", "ROLE_ABC,DEF", "ROLE_ABC=DEF", "ROLE_ABC_DEF",
             };
         final String expected = "ROLE_ABC_DEF";
 
         for (int i = 0; i < test.length; i++) {
             assertEquals("Unexpected granted authority name.", expected,
                 uut.getGrantedAuthority(test[i]).getAuthority());
         }
     }
    */
   
   /**
    * @return The InitialContextFactory for creating the root JNDI context; defaults to "com.sun.jndi.ldap.LdapCtxFactory"
    */
   public String getInitialContextFactory() {
       return initialContextFactory;
   }
   
   // ~ Methods
   // ================================================================
   
   /** 
    * Given a password, construct the Hashtable of JNDI values for a bind attempt.
    */
   protected Hashtable getJdniEnvironment(String password) {
       Hashtable env = new Hashtable(11);
       env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
       env.put(Context.PROVIDER_URL, getProviderURL());
       env.put(Context.SECURITY_AUTHENTICATION, authenticationType);
       env.put(Context.SECURITY_CREDENTIALS, password);
       return env;
   }
   
   /** 
    * @return The full "Provuder" URL for the LDAP source; it should look 
    *      something like:  ldap://www.mycompany.com:389/
    */
   public synchronized String getProviderURL() {
       if (null == this.providerUrl) {
           StringBuffer providerUrl = new StringBuffer( this.url );
           if (!this.url.endsWith("/")) {
               providerUrl.append("/");
           }
           providerUrl.append(this.rootContext);
           this.providerUrl = providerUrl.toString();
       }
       return this.providerUrl;
   }

   /**
    * @return Returns the roleUserAttributes.
    */
   public String getRoleAttributesSearchFilter() {
       return roleAttributesSearchFilter;
   }

   
   /**
    * @return Array of MessageFormat String's for Contexts that store role information for users.
    */
   public String[] getRoleContexts() {
       return roleContexts;
   }
   
   /**
    * @return Returns the roleNameAttributes.
    */
   public String[] getRoleNameAttributes() {
       return roleNameAttributes;
   }
   
   /**
    * @return Returns the rolePrefix.
    */
   public String getRolePrefix() {
       return rolePrefix;
   }
   

   protected Collection getRolesFromRoleSearch(UserContext userContext, String username, String[] roleAttributes) {
       if ((null == roleContexts) || (roleContexts.length == 0)) {
           return null;
       }
       String[] searchFilterVars = new String[] {userContext.userPrincipal, username};
       
       SearchControls controls = new SearchControls();
       controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
       controls.setReturningAttributes(roleAttributes);
       
       List roles = new ArrayList();
       for (int i = 0; i < roleContexts.length; i++) {
           try {
               NamingEnumeration results = userContext.dirContext.search(
                       roleContexts[i], roleAttributesSearchFilter, searchFilterVars, controls);
               addAnyRolesFound(results, roles);
           } catch (NamingException e) {
               if (log.isInfoEnabled()) { 
                   log.info("Unable to find user-role match in context = " + roleContexts[i], e);
               }
           }
       }
       return roles;
   }

   /**
    * Looksup any roleAttributes associated with the user's DN within the DirContext.
    * 
    * @param userContext
    *            UserContext Object containing DirContext in which to operate, and the user's DistinguishedName.
    * @param roleAttributes
    *            Names of all attributes to search for role name information.
    * @return Collection of roles granted to the user within the JNDI Context.
    * @throws NamingException
    */
   protected Collection getRolesFromUserContext(UserContext userContext, String[] roleAttributes)
           throws NamingException {
       List roles = new ArrayList();
       if (roleAttributes != null) {
           if (log.isDebugEnabled()) {
               StringBuffer rolesString = new StringBuffer();
   
               for (int i = 0; i < roleAttributes.length; i++) {
                   rolesString.append(", ");
                   rolesString.append(roleAttributes[i]);
               }
   
               log.debug("Searching user context '" + userContext.userPrincipal + "' for roles "
                       + "attributes: " + rolesString.substring(1));
           }
           Attributes attrs = userContext.dirContext.getAttributes(userContext.userPrincipal, roleAttributes);
           NamingEnumeration roleEnum = attrs.getAll();
           while (roleEnum.hasMore()) {
               Attribute roleAttr = (Attribute)roleEnum.next();
               for (int i = 0; i < roleAttr.size(); i++) {
                   roles.add( roleAttr.get(i) );
               }
           }
       }
       return roles;
   }
   
   /**
    * @return Returns the roleSuffix.
    */
   public String getRoleSuffix() {
       return roleSuffix;
   }

   /**
    * @return Returns the rootContext which to connect to; 
    *  typically it could look something like: dc=mycompany,dc=com.
    */
   public String getRootContext() {
       return rootContext;
   }
   
   /**
    * @return The LDAP URL to conntect to; example: ldap://ldap.mycompany.com:389/ 
    */
   public String getURL() {
       return url;
   }
   
   /** Attempts to bind to the userContexts; returning on the first successful bind; 
    *  or failing with a BadCredentialsException.
    * @param username
    * @param password
    * @return UserContext, an innerclass holding the DirContext, and the user's LDAP Principal String.
    * @throws NamingException
    * @throws BadCredentialsException
    */
   protected UserContext getUserContext(String username, String password) throws NamingException, BadCredentialsException {
       Hashtable env = getJdniEnvironment(password);
       UserContext userContext = new UserContext();
       for (int i = 0; i < userContexts.length; i++) {
           env.remove(Context.SECURITY_PRINCIPAL);
           userContext.userPrincipal = userContexts[i].format(new String[]{username});
           env.put(Context.SECURITY_PRINCIPAL, userContext.userPrincipal);
           try {
               userContext.dirContext = new InitialDirContext(env);
               if (userContext.dirContext != null) {
                   return userContext;
               }
           } catch (AuthenticationException ax) {
               if (log.isInfoEnabled()) {
                   log.info("Authentication exception for user.", ax);
               }
           }
       }
       throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE);
   }
   

   /**
    * @return Returns the userContexts.
    */
   public String[] getUserContexts() {
       String[] formats = new String[userContexts.length];
       for (int i = 0; i < userContexts.length; i++) {
           formats[i] = userContexts[i].toPattern();
       }
       return formats;
   }

   /**
    * @return Returns the userRolesAttributes.
    */
   public String[] getUserRolesAttributes() {
       return userRolesAttributes;
   }

   /**
    * @FIXME When using a search (see getRolesFromContext()) I don't think this
    *        extra check is needed; JNDI should be responible for returning
    *        only the attributes requested (or maybe I don't understand JNDI
    *        well enough).
    * 
    * @param Name/Id
    *            of the JNDI Attribute.
    * 
    * @return Return true if the given name is a role attribute.
    */
   protected boolean isRoleAttribute(String name) {
       log.info("Checking rolename: " + name);
       if (name != null) {
           for (int i = 0; i < userRolesAttributes.length; i++) {
               if (name.equals(userRolesAttributes[i])) {
                   return true;
               }
           }
       }
       return false;
   }
   
   /**
    * @return Returns the upperCaseRoleNames.
    */
   public boolean isUpperCaseRoleNames() {
       return upperCaseRoleNames;
   }
   
   

   public UserDetails loadUserByUsernameAndPassword(String username,
           String password) throws DataAccessException,
           BadCredentialsException {
       if ((password == null) || (password.length() == 0)) {
           throw new BadCredentialsException("Empty password");
       }

       try {
           if (log.isDebugEnabled()) {
               log.debug("Connecting to " + getProviderURL() + " as " + username);
           }

           UserContext userContext = getUserContext(username, password);

           Collection roles = getRolesFromUserContext(userContext, getUserRolesAttributes());
           Collection roles2 = getRolesFromRoleSearch(userContext, username, getRoleNameAttributes());
           if (null != roles2) {
               roles.addAll(roles2);
           }           
           
           userContext.dirContext.close();

           
           if (roles.isEmpty()) {
               if (null == defaultRole) {
                   throw new BadCredentialsException("The user has no granted "
                       + "authorities or the rolesAttribute is invalid");
               } else {
                   roles.add(defaultRole);
               }
           }

           String[] ldapRoles = (String[]) roles.toArray(new String[] {});
           
           return new User(username, password, true, true, true, true,
                   getGrantedAuthorities(ldapRoles));
       } catch (AuthenticationException ex) {
           throw new BadCredentialsException(
                   BAD_CREDENTIALS_EXCEPTION_MESSAGE, ex);
       } catch (CommunicationException ex) {
           throw new DataAccessResourceFailureException(ex.getRootCause()
                   .getMessage(), ex);
       } catch (NamingException ex) {
           throw new DataAccessResourceFailureException(ex.getMessage(), ex);
       }
   }
   
   /** If set to a non-null value, and a user can be bound to a LDAP Conext, 
    *  but no role information is found then this role is automatically added. 
    *  If null (the default) then a BadCredentialsException is thrown
    *  
    *  <p>For example; if you have an LDAP directory with no role information 
    *  stored, you might simply want to give any user who can login a role of "USER".</p>
    *  
    * @param defaultRole The defaultRole to set.
    */
   public void setDefaultRole(String defaultRole) {
       this.defaultRole = defaultRole;
   }

   /** The INITIAL_CONTEXT_FACTORY used to create the JNDI Factory.
    *  Default is "com.sun.jndi.ldap.LdapCtxFactory"; you <b>should not</b>
    *  need to set this unless you have unusual needs.
    *  
    * @param initialContextFactory The InitialContextFactory for creating the root JNDI context;
    *  defaults to "com.sun.jndi.ldap.LdapCtxFactory"
    */
   public void setInitialContextFactory(String initialContextFactory) {
       this.initialContextFactory = initialContextFactory;
   }

   /** Name(s) of the attribute(s) for a user account object 
    *  contaning role names assigned to the user.  Leave unset if there are none.
    *  Consult your LDAP server administrator to determine these value(s).
    *  
    * @param roleUserAttributes
    *            The roleUserAttributes to set.
    */
   public void setRoleAttributesSearchFilter(String roleAttributesSearchArgs) {
       this.roleAttributesSearchFilter = roleAttributesSearchArgs;
   }
   
   /** Shortcut for setRoleContexts( new String[]{roleContext} );  */
   public void setRoleContext(String roleContext) {
       setRoleContexts( new String[]{roleContext} );
   }

   /** Contexts to search for role's (which point to the user id).
    *  <p>Example, if you have a Groups object containing Groups of users then 
    *  the expression: <b>ou=Groups,dc=mycompany,dc=com</b> might be used;
    *  alternatively, if rootContext="dc=mycompany,dc=com" then simply use "ou=Groups" here.
    *  
    * @param roleContexts Array of MessageFormat String's for Contexts that store role information for users.
    */
   public void setRoleContexts(String[] roleContexts) {
       this.roleContexts = roleContexts;
   }
   
   /** Used to build LDAP Search Filter for finding roles (in the roleContexts) 
    *  pointing to a user.  Uses MessageFormat like tokens; {0} is the 
    *  user's DistiguishedName, {1} is the user's username. 
    *  For more information on syntax see  
    *  javax.naming.directory.DirContext.search(), or RFC 2254. 
    *  
    *  <p>Example: if each group has an attribute 'memberUid' with values being 
    *  the usernames of the user's in that group, then the value of this property 
    *  would be <b>(memberUid={1})</b> </p> 
    *  
    * @param roleNameAttributes The roleNameAttributes to set.
    */
   public void setRoleNameAttribute(String roleNameAttribute) {
       setRoleNameAttributes( new String[] {roleNameAttribute} );
   }
   
   /** Attribute(s) of any role object returned from the roleContexts to use as role-names. 
    *  <b>Warning: </b> if you do role lookups using the roleContexts and 
    *  roleAttributesSearchFilter then you need to set roleNameAttributes or ALL attributes 
    *  will be returned.
    *  
    * @param roleNameAttributes The roleNameAttributes to set.
    */
   public void setRoleNameAttributes(String[] roleNameAttributes) {
       this.roleNameAttributes = roleNameAttributes;
   }
   
   /** Prefix to be associated with any roles found for a user,
    *  defaults to an empty string.  
    *  Older versions of this class used "ROLE_" for this value. 
    *  
    * @param rolePrefix The rolePrefix to set.
    */
   public void setRolePrefix(String rolePrefix) {
       this.rolePrefix = rolePrefix;
   }
   
   /** Suffix to be associated with any roles found for a user,
    *  defaults to an empty string.
    *  
    * @param roleSuffix The roleSuffix to set.
    */
   public void setRoleSuffix(String roleSuffix) {
       this.roleSuffix = roleSuffix;
   }
   
   /** Root context of the LDAP Connection, if any is needed.  
    *  <p> Example: <b>dc=mycompany,dc=com</b> </p> 
    *  <p><strong>Note: </strong> It is usually preferable to add this data as part of the 
    *     userContexts and/or roleContexts attributes. </p> 
    *
    * @param rootContext The rootContext which to connect to; 
    *  typically it could look something like: dc=mycompany,dc=com.
    */
   public void setRootContext(String rootContext) {
       this.rootContext = rootContext;
   }
   
   /** If true then all role name values returned from the directory 
    *  will be converted to uppercase.
    *  
    * @param upperCaseRoleNames The upperCaseRoleNames to set.
    */
   public void setUpperCaseRoleNames(boolean upperCaseRoleNames) {
       this.upperCaseRoleNames = upperCaseRoleNames;
   }

   /**
    * @param host The LDAP URL to conntect to; example: ldap://ldap.mycompany.com:389/ 
    */
   public void setURL(String url) {
       this.url = url;
   }
   
   /** Shortcut for setUserContexts( new String[]{userContext} );  */
   public void setUserContext(String userContext) {
       setUserContexts( new String[]{userContext} );
   }

   /** One or more LDAP Contexts which contain user account information, use the 
    *  MessageFormat key {0} to denote location where the user's username should 
    *  be inserted into the expression to create a DistiguishedName.
    *  <p>Example: <p>cn={0},ou=Users,dc=mycompnay,dc=com</b> </p>
    *  <p>Alternatively, if you had set rootContext="dc=mycompany,dc=com" then 
    *    the first example would be rewritten as <b>cn={0},ou=Users</b>. </p>
    *    
    * @param userContexts
    *            The userContexts to set.
    */
   public void setUserContexts(String[] userContexts) {
       this.userContexts = new MessageFormat[userContexts.length];
       for (int i = 0; i < userContexts.length; i++) {
           this.userContexts[i] = new MessageFormat(userContexts[i]);
       }
   }
   
   /** Shortcut for setUserRolesAttributes(new String[]{userRolesAttribute}); */
   public void setUserRolesAttribute(String userRolesAttribute) {
       this.userRolesAttributes = new String[]{userRolesAttribute};
   }

   /** Attribute(s) of any role object returned from the roleContexts to use as role-names. 
    *  <b>Warning: </b> if you do role lookups using the roleContexts and 
    *  roleAttributesSearchFilter then you need to set roleNameAttributes or ALL attributes 
    *  will be returned.
    *  
    * @param userRolesAttributes
    *            The userRolesAttributes to set.
    */
   public void setUserRolesAttributes(String[] userRolesAttributes) {
       this.userRolesAttributes = userRolesAttributes;
   }

}

/*
 * Copyright 2002-2024 the original author or authors.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.AttributesMapperCallbackHandler;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.SearchExecutor;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.LdapUsernameToDnMapper;
import org.springframework.security.ldap.LdapUtils;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

/**
 * An Ldap implementation of UserDetailsManager.
 * <p>
 * It is designed around a standard setup where users and groups/roles are stored under
 * separate contexts, defined by the "userDnBase" and "groupSearchBase" properties
 * respectively.
 * <p>
 * In this case, LDAP is being used purely to retrieve information and this class can be
 * used in place of any other UserDetailsService for authentication. Authentication isn't
 * performed directly against the directory, unlike with the LDAP authentication provider
 * setup.
 *
 * @author Luke Taylor
 * @author Josh Cummings
 * @since 2.0
 */
public class LdapUserDetailsManager implements UserDetailsManager {

	private final Log logger = LogFactory.getLog(LdapUserDetailsManager.class);

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	/**
	 * The strategy for mapping usernames to LDAP distinguished names. This will be used
	 * when building DNs for creating new users etc.
	 */
	LdapUsernameToDnMapper usernameMapper = new DefaultLdapUsernameToDnMapper("cn=users", "uid");

	/** The DN under which groups are stored */
	private LdapName groupSearchBase = LdapNameBuilder.newInstance("cn=groups").build();

	/** Password attribute name */
	private String passwordAttributeName = "userPassword";

	/** The attribute which corresponds to the role name of a group. */
	private String groupRoleAttributeName = "cn";

	/** The attribute which contains members of a group */
	private String groupMemberAttributeName = "uniquemember";

	private String rolePrefix = "ROLE_";

	/** The pattern to be used for the user search. {0} is the user's DN */
	private String groupSearchFilter = "(uniquemember={0})";

	/**
	 * The strategy used to create a UserDetails object from the LDAP context, username
	 * and list of authorities. This should be set to match the required UserDetails
	 * implementation.
	 */
	private UserDetailsContextMapper userDetailsMapper = new InetOrgPersonContextMapper();

	private final LdapTemplate template;

	/** Default context mapper used to create a set of roles from a list of attributes */
	private AttributesMapper<GrantedAuthority> roleMapper = (attributes) -> {
		Attribute roleAttr = attributes.get(this.groupRoleAttributeName);
		NamingEnumeration<?> ne = roleAttr.getAll();
		Object group = ne.next();
		String role = group.toString();
		return new SimpleGrantedAuthority(this.rolePrefix + role.toUpperCase(Locale.ROOT));
	};

	private String[] attributesToRetrieve;

	private boolean usePasswordModifyExtensionOperation = false;

	public LdapUserDetailsManager(ContextSource contextSource) {
		this.template = new LdapTemplate(contextSource);
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		LdapName dn = this.usernameMapper.buildLdapName(username);
		List<GrantedAuthority> authorities = getUserAuthorities(dn, username);
		this.logger.debug(LogMessage.format("Loading user '%s' with DN '%s'", username, dn));
		DirContextAdapter userCtx = loadUserAsContext(dn, username);
		return this.userDetailsMapper.mapUserFromContext(userCtx, username, authorities);
	}

	private DirContextAdapter loadUserAsContext(final LdapName dn, final String username) {
		return this.template.executeReadOnly((ctx) -> {
			try {
				Attributes attrs = ctx.getAttributes(dn, this.attributesToRetrieve);
				return new DirContextAdapter(attrs, LdapUtils.getFullDn(dn, ctx));
			}
			catch (NameNotFoundException ex) {
				throw new UsernameNotFoundException("User " + username + " not found", ex);
			}
		});
	}

	/**
	 * Changes the password for the current user. The username is obtained from the
	 * security context.
	 *
	 * <p>
	 * There are two supported strategies for modifying the user's password depending on
	 * the capabilities of the corresponding LDAP server.
	 *
	 * <p>
	 * Configured one way, this method will modify the user's password via the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062"> LDAP Password Modify
	 * Extended Operation </a>.
	 *
	 * <p>
	 * See {@link LdapUserDetailsManager#setUsePasswordModifyExtensionOperation(boolean)}
	 * for details.
	 * </p>
	 *
	 * <p>
	 * By default, though, if the old password is supplied, the update will be made by
	 * rebinding as the user, thus modifying the password using the user's permissions. If
	 * <code>oldPassword</code> is null, the update will be attempted using a standard
	 * read/write context supplied by the context source.
	 * </p>
	 * @param oldPassword the old password
	 * @param newPassword the new value of the password.
	 */
	@Override
	public void changePassword(final String oldPassword, final String newPassword) {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		Assert.notNull(authentication,
				"No authentication object found in security context. Can't change current user's password!");
		String username = authentication.getName();
		this.logger.debug(LogMessage.format("Changing password for user '%s'", username));
		LdapName userDn = this.usernameMapper.buildLdapName(username);
		if (this.usePasswordModifyExtensionOperation) {
			changePasswordUsingExtensionOperation(userDn, oldPassword, newPassword);
		}
		else {
			changePasswordUsingAttributeModification(userDn, oldPassword, newPassword);
		}
	}

	/**
	 * @param dn the distinguished name of the entry - may be either relative to the base
	 * context or a complete DN including the name of the context (either is supported).
	 * @param username the user whose roles are required.
	 * @return the granted authorities returned by the group search
	 */
	List<GrantedAuthority> getUserAuthorities(final LdapName dn, final String username) {
		SearchExecutor se = (ctx) -> {
			LdapName fullDn = LdapUtils.getFullDn(dn, ctx);
			SearchControls ctrls = new SearchControls();
			ctrls.setReturningAttributes(new String[] { this.groupRoleAttributeName });
			return ctx.search(this.groupSearchBase, this.groupSearchFilter,
					new String[] { fullDn.toString(), username }, ctrls);
		};
		AttributesMapperCallbackHandler<GrantedAuthority> roleCollector = new AttributesMapperCallbackHandler<>(
				this.roleMapper);
		this.template.search(se, roleCollector);
		return roleCollector.getList();
	}

	@Override
	public void createUser(UserDetails user) {
		DirContextAdapter ctx = new DirContextAdapter();
		copyToContext(user, ctx);
		LdapName dn = this.usernameMapper.buildLdapName(user.getUsername());
		this.logger.debug(LogMessage.format("Creating new user '%s' with DN '%s'", user.getUsername(), dn));
		this.template.bind(dn, ctx, null);
		// Check for any existing authorities which might be set for this
		// DN and remove them
		List<GrantedAuthority> authorities = getUserAuthorities(dn, user.getUsername());
		if (!authorities.isEmpty()) {
			removeAuthorities(dn, authorities);
		}
		addAuthorities(dn, user.getAuthorities());
	}

	@Override
	public void updateUser(UserDetails user) {
		LdapName dn = this.usernameMapper.buildLdapName(user.getUsername());
		this.logger.debug(LogMessage.format("Updating new user '%s' with DN '%s'", user.getUsername(), dn));
		List<GrantedAuthority> authorities = getUserAuthorities(dn, user.getUsername());
		DirContextAdapter ctx = loadUserAsContext(dn, user.getUsername());
		ctx.setUpdateMode(true);
		copyToContext(user, ctx);
		// Remove the objectclass attribute from the list of mods (if present).
		List<ModificationItem> mods = new LinkedList<>(Arrays.asList(ctx.getModificationItems()));
		ListIterator<ModificationItem> modIt = mods.listIterator();
		while (modIt.hasNext()) {
			ModificationItem mod = modIt.next();
			Attribute a = mod.getAttribute();
			if ("objectclass".equalsIgnoreCase(a.getID())) {
				modIt.remove();
			}
		}
		this.template.modifyAttributes(dn, mods.toArray(new ModificationItem[0]));
		// template.rebind(dn, ctx, null);
		// Remove the old authorities and replace them with the new one
		removeAuthorities(dn, authorities);
		addAuthorities(dn, user.getAuthorities());
	}

	@Override
	public void deleteUser(String username) {
		LdapName dn = this.usernameMapper.buildLdapName(username);
		removeAuthorities(dn, getUserAuthorities(dn, username));
		this.template.unbind(dn);
	}

	@Override
	public boolean userExists(String username) {
		LdapName dn = this.usernameMapper.buildLdapName(username);
		try {
			Object obj = this.template.lookup(dn);
			if (obj instanceof Context) {
				LdapUtils.closeContext((Context) obj);
			}
			return true;
		}
		catch (org.springframework.ldap.NameNotFoundException ex) {
			return false;
		}
	}

	/**
	 * Creates a DN from a group name.
	 * @param group the name of the group
	 * @return the DN of the corresponding group, including the groupSearchBase
	 * @deprecated
	 */
	@Deprecated
	protected DistinguishedName buildGroupDn(String group) {
		DistinguishedName dn = new DistinguishedName(this.groupSearchBase);
		dn.add(this.groupRoleAttributeName, group.toLowerCase(Locale.ROOT));
		return dn;
	}

	protected LdapName buildGroupName(String group) {
		return LdapNameBuilder.newInstance(buildGroupDn(group)).build();
	}

	protected void copyToContext(UserDetails user, DirContextAdapter ctx) {
		this.userDetailsMapper.mapUserToContext(user, ctx);
	}

	@Deprecated
	protected void addAuthorities(DistinguishedName userDn, Collection<? extends GrantedAuthority> authorities) {
		modifyAuthorities(LdapNameBuilder.newInstance(userDn).build(), authorities, DirContext.ADD_ATTRIBUTE);
	}

	protected void addAuthorities(LdapName userDn, Collection<? extends GrantedAuthority> authorities) {
		addAuthorities(new DistinguishedName(userDn), authorities);
	}

	@Deprecated
	protected void removeAuthorities(DistinguishedName userDn, Collection<? extends GrantedAuthority> authorities) {
		modifyAuthorities(LdapNameBuilder.newInstance(userDn).build(), authorities, DirContext.REMOVE_ATTRIBUTE);
	}

	protected void removeAuthorities(LdapName userDn, Collection<? extends GrantedAuthority> authorities) {
		removeAuthorities(new DistinguishedName(userDn), authorities);
	}

	private void modifyAuthorities(final LdapName userDn, final Collection<? extends GrantedAuthority> authorities,
			final int modType) {
		this.template.executeReadWrite((ctx) -> {
			for (GrantedAuthority authority : authorities) {
				String group = convertAuthorityToGroup(authority);
				LdapName fullDn = LdapUtils.getFullDn(userDn, ctx);
				ModificationItem addGroup = new ModificationItem(modType,
						new BasicAttribute(this.groupMemberAttributeName, fullDn.toString()));
				ctx.modifyAttributes(buildGroupName(group), new ModificationItem[] { addGroup });
			}
			return null;
		});
	}

	private String convertAuthorityToGroup(GrantedAuthority authority) {
		String group = authority.getAuthority();
		if (group.startsWith(this.rolePrefix)) {
			group = group.substring(this.rolePrefix.length());
		}
		return group;
	}

	public void setUsernameMapper(LdapUsernameToDnMapper usernameMapper) {
		this.usernameMapper = usernameMapper;
	}

	public void setPasswordAttributeName(String passwordAttributeName) {
		this.passwordAttributeName = passwordAttributeName;
	}

	public void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = LdapNameBuilder.newInstance(groupSearchBase).build();
	}

	public void setGroupRoleAttributeName(String groupRoleAttributeName) {
		this.groupRoleAttributeName = groupRoleAttributeName;
	}

	public void setAttributesToRetrieve(String[] attributesToRetrieve) {
		Assert.notNull(attributesToRetrieve, "attributesToRetrieve cannot be null");
		this.attributesToRetrieve = attributesToRetrieve;
	}

	public void setUserDetailsMapper(UserDetailsContextMapper userDetailsMapper) {
		this.userDetailsMapper = userDetailsMapper;
	}

	/**
	 * Sets the name of the multi-valued attribute which holds the DNs of users who are
	 * members of a group.
	 * <p>
	 * Usually this will be <tt>uniquemember</tt> (the default value) or <tt>member</tt>.
	 * </p>
	 * @param groupMemberAttributeName the name of the attribute used to store group
	 * members.
	 */
	public void setGroupMemberAttributeName(String groupMemberAttributeName) {
		Assert.hasText(groupMemberAttributeName, "groupMemberAttributeName should have text");
		this.groupMemberAttributeName = groupMemberAttributeName;
		this.groupSearchFilter = "(" + groupMemberAttributeName + "={0})";
	}

	public void setRoleMapper(AttributesMapper roleMapper) {
		this.roleMapper = roleMapper;
	}

	/**
	 * Sets the method by which a user's password gets modified.
	 *
	 * <p>
	 * If set to {@code true}, then {@link LdapUserDetailsManager#changePassword} will
	 * modify the user's password by way of the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062">Password Modify
	 * Extension Operation</a>.
	 *
	 * <p>
	 * If set to {@code false}, then {@link LdapUserDetailsManager#changePassword} will
	 * modify the user's password by directly modifying attributes on the corresponding
	 * entry.
	 *
	 * <p>
	 * Before using this setting, ensure that the corresponding LDAP server supports this
	 * extended operation.
	 *
	 * <p>
	 * By default, {@code usePasswordModifyExtensionOperation} is false.
	 * @param usePasswordModifyExtensionOperation whether to use the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062">Password Modify
	 * Extension Operation</a> to modify the password
	 * @since 4.2.9
	 */
	public void setUsePasswordModifyExtensionOperation(boolean usePasswordModifyExtensionOperation) {
		this.usePasswordModifyExtensionOperation = usePasswordModifyExtensionOperation;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Sets the role prefix used when converting authorities. The default value is "ROLE_"
	 * @param rolePrefix role prefix
	 * @since 6.3
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "A rolePrefix must be supplied");
		this.rolePrefix = rolePrefix;
	}

	private void changePasswordUsingAttributeModification(LdapName userDn, String oldPassword, String newPassword) {
		ModificationItem[] passwordChange = new ModificationItem[] { new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
				new BasicAttribute(this.passwordAttributeName, newPassword)) };
		if (oldPassword == null) {
			this.template.modifyAttributes(userDn, passwordChange);
			return;
		}
		this.template.executeReadWrite((dirCtx) -> {
			LdapContext ctx = (LdapContext) dirCtx;
			ctx.removeFromEnvironment("com.sun.jndi.ldap.connect.pool");
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, LdapUtils.getFullDn(userDn, ctx).toString());
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, oldPassword);
			// TODO: reconnect doesn't appear to actually change the credentials
			try {
				ctx.reconnect(null);
			}
			catch (javax.naming.AuthenticationException ex) {
				throw new BadCredentialsException("Authentication for password change failed.");
			}
			ctx.modifyAttributes(userDn, passwordChange);
			return null;
		});
	}

	private void changePasswordUsingExtensionOperation(LdapName userDn, String oldPassword, String newPassword) {
		this.template.executeReadWrite((dirCtx) -> {
			LdapContext ctx = (LdapContext) dirCtx;
			String userIdentity = LdapUtils.getFullDn(userDn, ctx).toString();
			PasswordModifyRequest request = new PasswordModifyRequest(userIdentity, oldPassword, newPassword);
			try {
				return ctx.extendedOperation(request);
			}
			catch (javax.naming.AuthenticationException ex) {
				throw new BadCredentialsException("Authentication for password change failed.");
			}
		});
	}

	/**
	 * An implementation of the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062"> LDAP Password Modify
	 * Extended Operation </a> client request.
	 *
	 * <p>
	 * Can be directed at any LDAP server that supports the Password Modify Extended
	 * Operation.
	 *
	 * @author Josh Cummings
	 * @since 4.2.9
	 */
	private static class PasswordModifyRequest implements ExtendedRequest {

		@Serial
		private static final long serialVersionUID = 3154223576081503237L;

		private static final byte SEQUENCE_TYPE = 48;

		private static final String PASSWORD_MODIFY_OID = "1.3.6.1.4.1.4203.1.11.1";

		private static final byte USER_IDENTITY_OCTET_TYPE = -128;

		private static final byte OLD_PASSWORD_OCTET_TYPE = -127;

		private static final byte NEW_PASSWORD_OCTET_TYPE = -126;

		private final ByteArrayOutputStream value = new ByteArrayOutputStream();

		PasswordModifyRequest(String userIdentity, String oldPassword, String newPassword) {
			ByteArrayOutputStream elements = new ByteArrayOutputStream();
			if (userIdentity != null) {
				berEncode(USER_IDENTITY_OCTET_TYPE, userIdentity.getBytes(), elements);
			}
			if (oldPassword != null) {
				berEncode(OLD_PASSWORD_OCTET_TYPE, oldPassword.getBytes(), elements);
			}
			if (newPassword != null) {
				berEncode(NEW_PASSWORD_OCTET_TYPE, newPassword.getBytes(), elements);
			}
			berEncode(SEQUENCE_TYPE, elements.toByteArray(), this.value);
		}

		@Override
		public String getID() {
			return PASSWORD_MODIFY_OID;
		}

		@Override
		public byte[] getEncodedValue() {
			return this.value.toByteArray();
		}

		@Override
		public ExtendedResponse createExtendedResponse(String id, byte[] berValue, int offset, int length) {
			return null;
		}

		/**
		 * Only minimal support for <a target="_blank" href=
		 * "https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf"> BER
		 * encoding </a>; just what is necessary for the Password Modify request.
		 *
		 */
		private void berEncode(byte type, byte[] src, ByteArrayOutputStream dest) {
			int length = src.length;
			dest.write(type);
			if (length < 128) {
				dest.write(length);
			}
			else if ((length & 0x0000_00FF) == length) {
				dest.write((byte) 0x81);
				dest.write((byte) (length & 0xFF));
			}
			else if ((length & 0x0000_FFFF) == length) {
				dest.write((byte) 0x82);
				dest.write((byte) ((length >> 8) & 0xFF));
				dest.write((byte) (length & 0xFF));
			}
			else if ((length & 0x00FF_FFFF) == length) {
				dest.write((byte) 0x83);
				dest.write((byte) ((length >> 16) & 0xFF));
				dest.write((byte) ((length >> 8) & 0xFF));
				dest.write((byte) (length & 0xFF));
			}
			else {
				dest.write((byte) 0x84);
				dest.write((byte) ((length >> 24) & 0xFF));
				dest.write((byte) ((length >> 16) & 0xFF));
				dest.write((byte) ((length >> 8) & 0xFF));
				dest.write((byte) (length & 0xFF));
			}
			try {
				dest.write(src);
			}
			catch (IOException ex) {
				throw new IllegalArgumentException("Failed to BER encode provided value of type: " + type);
			}
		}

	}

}

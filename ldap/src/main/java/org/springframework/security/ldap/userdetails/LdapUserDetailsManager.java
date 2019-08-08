/*
 * Copyright 2002-2018 the original author or authors.
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
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.AttributesMapperCallbackHandler;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.SearchExecutor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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

	/**
	 * The strategy for mapping usernames to LDAP distinguished names. This will be used
	 * when building DNs for creating new users etc.
	 */
	LdapUsernameToDnMapper usernameMapper = new DefaultLdapUsernameToDnMapper("cn=users",
			"uid");

	/** The DN under which groups are stored */
	private DistinguishedName groupSearchBase = new DistinguishedName("cn=groups");

	/** Password attribute name */
	private String passwordAttributeName = "userPassword";

	/** The attribute which corresponds to the role name of a group. */
	private String groupRoleAttributeName = "cn";
	/** The attribute which contains members of a group */
	private String groupMemberAttributeName = "uniquemember";

	private final String rolePrefix = "ROLE_";

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
	private AttributesMapper roleMapper = attributes -> {
		Attribute roleAttr = attributes.get(groupRoleAttributeName);

		NamingEnumeration<?> ne = roleAttr.getAll();
		// assert ne.hasMore();
		Object group = ne.next();
		String role = group.toString();

		return new SimpleGrantedAuthority(rolePrefix + role.toUpperCase());
	};

	private String[] attributesToRetrieve;

	private boolean usePasswordModifyExtensionOperation = false;

	public LdapUserDetailsManager(ContextSource contextSource) {
		template = new LdapTemplate(contextSource);
	}

	public UserDetails loadUserByUsername(String username) {
		DistinguishedName dn = usernameMapper.buildDn(username);
		List<GrantedAuthority> authorities = getUserAuthorities(dn, username);

		logger.debug("Loading user '" + username + "' with DN '" + dn + "'");

		DirContextAdapter userCtx = loadUserAsContext(dn, username);

		return userDetailsMapper.mapUserFromContext(userCtx, username, authorities);
	}

	private DirContextAdapter loadUserAsContext(final DistinguishedName dn,
			final String username) {
		return (DirContextAdapter) template.executeReadOnly((ContextExecutor) ctx -> {
			try {
				Attributes attrs = ctx.getAttributes(dn, attributesToRetrieve);
				return new DirContextAdapter(attrs, LdapUtils.getFullDn(dn, ctx));
			}
			catch (NameNotFoundException notFound) {
				throw new UsernameNotFoundException(
						"User " + username + " not found", notFound);
			}
		});
	}

	/**
	 * Changes the password for the current user. The username is obtained from the
	 * security context.
	 *
	 * There are two supported strategies for modifying the user's password depending on
	 * the capabilities of the corresponding LDAP server.
	 *
	 * <p>
	 * Configured one way, this method will modify the user's password via the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062">
	 *     LDAP Password Modify Extended Operation
	 * </a>.
	 *
	 * See {@link LdapUserDetailsManager#setUsePasswordModifyExtensionOperation(boolean)} for details.
	 * </p>
	 *
	 * <p>
	 * By default, though, if the old password is supplied, the update will be made by rebinding as the user,
	 * thus modifying the password using the user's permissions. If
	 * <code>oldPassword</code> is null, the update will be attempted using a standard
	 * read/write context supplied by the context source.
	 * </p>
	 *
	 * @param oldPassword the old password
	 * @param newPassword the new value of the password.
	 */
	public void changePassword(final String oldPassword, final String newPassword) {
		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();
		Assert.notNull(
				authentication,
				"No authentication object found in security context. Can't change current user's password!");

		String username = authentication.getName();

		logger.debug("Changing password for user '" + username);

		DistinguishedName userDn = usernameMapper.buildDn(username);

		if (usePasswordModifyExtensionOperation) {
			changePasswordUsingExtensionOperation(userDn, oldPassword, newPassword);
		} else {
			changePasswordUsingAttributeModification(userDn, oldPassword, newPassword);
		}
	}

	/**
	 *
	 * @param dn the distinguished name of the entry - may be either relative to the base
	 * context or a complete DN including the name of the context (either is supported).
	 * @param username the user whose roles are required.
	 * @return the granted authorities returned by the group search
	 */
	@SuppressWarnings("unchecked")
	List<GrantedAuthority> getUserAuthorities(final DistinguishedName dn,
			final String username) {
		SearchExecutor se = ctx -> {
			DistinguishedName fullDn = LdapUtils.getFullDn(dn, ctx);
			SearchControls ctrls = new SearchControls();
			ctrls.setReturningAttributes(new String[] { groupRoleAttributeName });

			return ctx.search(groupSearchBase, groupSearchFilter, new String[] {
					fullDn.toUrl(), username }, ctrls);
		};

		AttributesMapperCallbackHandler roleCollector = new AttributesMapperCallbackHandler(
				roleMapper);

		template.search(se, roleCollector);
		return roleCollector.getList();
	}

	public void createUser(UserDetails user) {
		DirContextAdapter ctx = new DirContextAdapter();
		copyToContext(user, ctx);
		DistinguishedName dn = usernameMapper.buildDn(user.getUsername());

		logger.debug("Creating new user '" + user.getUsername() + "' with DN '" + dn
				+ "'");

		template.bind(dn, ctx, null);

		// Check for any existing authorities which might be set for this DN and remove
		// them
		List<GrantedAuthority> authorities = getUserAuthorities(dn, user.getUsername());

		if (authorities.size() > 0) {
			removeAuthorities(dn, authorities);
		}

		addAuthorities(dn, user.getAuthorities());
	}

	public void updateUser(UserDetails user) {
		DistinguishedName dn = usernameMapper.buildDn(user.getUsername());

		logger.debug("Updating user '" + user.getUsername() + "' with DN '" + dn + "'");

		List<GrantedAuthority> authorities = getUserAuthorities(dn, user.getUsername());

		DirContextAdapter ctx = loadUserAsContext(dn, user.getUsername());
		ctx.setUpdateMode(true);
		copyToContext(user, ctx);

		// Remove the objectclass attribute from the list of mods (if present).
		List<ModificationItem> mods = new LinkedList<>(Arrays.asList(ctx
				.getModificationItems()));
		ListIterator<ModificationItem> modIt = mods.listIterator();

		while (modIt.hasNext()) {
			ModificationItem mod = modIt.next();
			Attribute a = mod.getAttribute();
			if ("objectclass".equalsIgnoreCase(a.getID())) {
				modIt.remove();
			}
		}

		template.modifyAttributes(dn, mods.toArray(new ModificationItem[0]));

		// template.rebind(dn, ctx, null);
		// Remove the old authorities and replace them with the new one
		removeAuthorities(dn, authorities);
		addAuthorities(dn, user.getAuthorities());
	}

	public void deleteUser(String username) {
		DistinguishedName dn = usernameMapper.buildDn(username);
		removeAuthorities(dn, getUserAuthorities(dn, username));
		template.unbind(dn);
	}

	public boolean userExists(String username) {
		DistinguishedName dn = usernameMapper.buildDn(username);

		try {
			Object obj = template.lookup(dn);
			if (obj instanceof Context) {
				LdapUtils.closeContext((Context) obj);
			}
			return true;
		}
		catch (org.springframework.ldap.NameNotFoundException e) {
			return false;
		}
	}

	/**
	 * Creates a DN from a group name.
	 *
	 * @param group the name of the group
	 * @return the DN of the corresponding group, including the groupSearchBase
	 */
	protected DistinguishedName buildGroupDn(String group) {
		DistinguishedName dn = new DistinguishedName(groupSearchBase);
		dn.add(groupRoleAttributeName, group.toLowerCase());

		return dn;
	}

	protected void copyToContext(UserDetails user, DirContextAdapter ctx) {
		userDetailsMapper.mapUserToContext(user, ctx);
	}

	protected void addAuthorities(DistinguishedName userDn,
			Collection<? extends GrantedAuthority> authorities) {
		modifyAuthorities(userDn, authorities, DirContext.ADD_ATTRIBUTE);
	}

	protected void removeAuthorities(DistinguishedName userDn,
			Collection<? extends GrantedAuthority> authorities) {
		modifyAuthorities(userDn, authorities, DirContext.REMOVE_ATTRIBUTE);
	}

	private void modifyAuthorities(final DistinguishedName userDn,
			final Collection<? extends GrantedAuthority> authorities, final int modType) {
		template.executeReadWrite((ContextExecutor) ctx -> {
			for (GrantedAuthority authority : authorities) {
				String group = convertAuthorityToGroup(authority);
				DistinguishedName fullDn = LdapUtils.getFullDn(userDn, ctx);
				ModificationItem addGroup = new ModificationItem(modType,
						new BasicAttribute(groupMemberAttributeName, fullDn.toUrl()));

				ctx.modifyAttributes(buildGroupDn(group),
						new ModificationItem[] { addGroup });
			}
			return null;
		});
	}

	private String convertAuthorityToGroup(GrantedAuthority authority) {
		String group = authority.getAuthority();

		if (group.startsWith(rolePrefix)) {
			group = group.substring(rolePrefix.length());
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
		this.groupSearchBase = new DistinguishedName(groupSearchBase);
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
	 *
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
	 * If set to {@code true}, then {@link LdapUserDetailsManager#changePassword} will modify
	 * the user's password by way of the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062">Password Modify Extension Operation</a>.
	 *
	 * If set to {@code false}, then {@link LdapUserDetailsManager#changePassword} will modify
	 * the user's password by directly modifying attributes on the corresponding entry.
	 *
	 * Before using this setting, ensure that the corresponding LDAP server supports this extended operation.
	 *
	 * By default, {@code usePasswordModifyExtensionOperation} is false.
	 *
	 * @param usePasswordModifyExtensionOperation
	 * @since 4.2.9
	 */
	public void setUsePasswordModifyExtensionOperation(boolean usePasswordModifyExtensionOperation) {
		this.usePasswordModifyExtensionOperation = usePasswordModifyExtensionOperation;
	}

	private void changePasswordUsingAttributeModification
			(DistinguishedName userDn, String oldPassword, String newPassword) {

		final ModificationItem[] passwordChange = new ModificationItem[] { new ModificationItem(
				DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(passwordAttributeName,
				newPassword)) };

		if (oldPassword == null) {
			template.modifyAttributes(userDn, passwordChange);
			return;
		}

		template.executeReadWrite(dirCtx -> {
			LdapContext ctx = (LdapContext) dirCtx;
			ctx.removeFromEnvironment("com.sun.jndi.ldap.connect.pool");
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL,
					LdapUtils.getFullDn(userDn, ctx).toString());
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, oldPassword);
			// TODO: reconnect doesn't appear to actually change the credentials
			try {
				ctx.reconnect(null);
			} catch (javax.naming.AuthenticationException e) {
				throw new BadCredentialsException(
						"Authentication for password change failed.");
			}

			ctx.modifyAttributes(userDn, passwordChange);

			return null;
		});

	}

	private void changePasswordUsingExtensionOperation
			(DistinguishedName userDn, String oldPassword, String newPassword) {

		template.executeReadWrite(dirCtx -> {
			LdapContext ctx = (LdapContext) dirCtx;

			String userIdentity = LdapUtils.getFullDn(userDn, ctx).encode();
			PasswordModifyRequest request =
					new PasswordModifyRequest(userIdentity, oldPassword, newPassword);

			try {
				return ctx.extendedOperation(request);
			} catch (javax.naming.AuthenticationException e) {
				throw new BadCredentialsException(
						"Authentication for password change failed.");
			}
		});
	}

	/**
	 * An implementation of the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc3062">
	 *    LDAP Password Modify Extended Operation
	 * </a>
	 * client request.
	 *
	 * Can be directed at any LDAP server that supports the Password Modify Extended Operation.
	 *
	 * @author Josh Cummings
	 * @since 4.2.9
	 */
	private static class PasswordModifyRequest implements ExtendedRequest {
		private static final byte SEQUENCE_TYPE = 48;

		private static final String PASSWORD_MODIFY_OID = "1.3.6.1.4.1.4203.1.11.1";
		private static final byte USER_IDENTITY_OCTET_TYPE = -128;
		private static final byte OLD_PASSWORD_OCTET_TYPE = -127;
		private static final byte NEW_PASSWORD_OCTET_TYPE = -126;

		private final ByteArrayOutputStream value = new ByteArrayOutputStream();

		public PasswordModifyRequest(String userIdentity, String oldPassword, String newPassword) {
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
		 * Only minimal support for
		 * <a target="_blank" href="https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf">
		 *     BER encoding
		 * </a>; just what is necessary for the Password Modify request.
		 *
		 */
		private void berEncode(byte type, byte[] src, ByteArrayOutputStream dest) {
			int length = src.length;

			dest.write(type);

			if (length < 128) {
				dest.write(length);
			} else if ((length & 0x0000_00FF) == length) {
				dest.write((byte) 0x81);
				dest.write((byte) (length & 0xFF));
			} else if ((length & 0x0000_FFFF) == length) {
				dest.write((byte) 0x82);
				dest.write((byte) ((length >> 8) & 0xFF));
				dest.write((byte) (length & 0xFF));
			} else if ((length & 0x00FF_FFFF) == length) {
				dest.write((byte) 0x83);
				dest.write((byte) ((length >> 16) & 0xFF));
				dest.write((byte) ((length >> 8) & 0xFF));
				dest.write((byte) (length & 0xFF));
			} else {
				dest.write((byte) 0x84);
				dest.write((byte) ((length >> 24) & 0xFF));
				dest.write((byte) ((length >> 16) & 0xFF));
				dest.write((byte) ((length >> 8) & 0xFF));
				dest.write((byte) (length & 0xFF));
			}

			try {
				dest.write(src);
			} catch (IOException e) {
				throw new IllegalArgumentException("Failed to BER encode provided value of type: " + type);
			}
		}
	}
}

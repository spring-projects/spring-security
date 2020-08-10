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
package org.springframework.security.acls.domain;

import java.util.List;

import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

public class DefaultPermissionGrantingStrategy implements PermissionGrantingStrategy {

	private final transient AuditLogger auditLogger;

	/**
	 * Creates an instance with the logger which will be used to record granting and
	 * denial of requested permissions.
	 */
	public DefaultPermissionGrantingStrategy(AuditLogger auditLogger) {
		Assert.notNull(auditLogger, "auditLogger cannot be null");
		this.auditLogger = auditLogger;
	}

	/**
	 * Determines authorization. The order of the <code>permission</code> and
	 * <code>sid</code> arguments is <em>extremely important</em>! The method will iterate
	 * through each of the <code>permission</code>s in the order specified. For each
	 * iteration, all of the <code>sid</code>s will be considered, again in the order they
	 * are presented. A search will then be performed for the first
	 * {@link AccessControlEntry} object that directly matches that
	 * <code>permission:sid</code> combination. When the <em>first full match</em> is
	 * found (ie an ACE that has the SID currently being searched for and the exact
	 * permission bit mask being search for), the grant or deny flag for that ACE will
	 * prevail. If the ACE specifies to grant access, the method will return
	 * <code>true</code>. If the ACE specifies to deny access, the loop will stop and the
	 * next <code>permission</code> iteration will be performed. If each permission
	 * indicates to deny access, the first deny ACE found will be considered the reason
	 * for the failure (as it was the first match found, and is therefore the one most
	 * logically requiring changes - although not always). If absolutely no matching ACE
	 * was found at all for any permission, the parent ACL will be tried (provided that
	 * there is a parent and {@link Acl#isEntriesInheriting()} is <code>true</code>. The
	 * parent ACL will also scan its parent and so on. If ultimately no matching ACE is
	 * found, a <code>NotFoundException</code> will be thrown and the caller will need to
	 * decide how to handle the permission check. Similarly, if any of the SID arguments
	 * presented to the method were not loaded by the ACL,
	 * <code>UnloadedSidException</code> will be thrown.
	 * @param permission the exact permissions to scan for (order is important)
	 * @param sids the exact SIDs to scan for (order is important)
	 * @param administrativeMode if <code>true</code> denotes the query is for
	 * administrative purposes and no auditing will be undertaken
	 * @return <code>true</code> if one of the permissions has been granted,
	 * <code>false</code> if one of the permissions has been specifically revoked
	 * @throws NotFoundException if an exact ACE for one of the permission bit masks and
	 * SID combination could not be found
	 */
	public boolean isGranted(Acl acl, List<Permission> permission, List<Sid> sids, boolean administrativeMode)
			throws NotFoundException {

		final List<AccessControlEntry> aces = acl.getEntries();

		AccessControlEntry firstRejection = null;

		for (Permission p : permission) {
			for (Sid sid : sids) {
				// Attempt to find exact match for this permission mask and SID
				boolean scanNextSid = true;

				for (AccessControlEntry ace : aces) {

					if (isGranted(ace, p) && ace.getSid().equals(sid)) {
						// Found a matching ACE, so its authorization decision will
						// prevail
						if (ace.isGranting()) {
							// Success
							if (!administrativeMode) {
								auditLogger.logIfNeeded(true, ace);
							}

							return true;
						}

						// Failure for this permission, so stop search
						// We will see if they have a different permission
						// (this permission is 100% rejected for this SID)
						if (firstRejection == null) {
							// Store first rejection for auditing reasons
							firstRejection = ace;
						}

						scanNextSid = false; // helps break the loop

						break; // exit aces loop
					}
				}

				if (!scanNextSid) {
					break; // exit SID for loop (now try next permission)
				}
			}
		}

		if (firstRejection != null) {
			// We found an ACE to reject the request at this point, as no
			// other ACEs were found that granted a different permission
			if (!administrativeMode) {
				auditLogger.logIfNeeded(false, firstRejection);
			}

			return false;
		}

		// No matches have been found so far
		if (acl.isEntriesInheriting() && (acl.getParentAcl() != null)) {
			// We have a parent, so let them try to find a matching ACE
			return acl.getParentAcl().isGranted(permission, sids, false);
		}
		else {
			// We either have no parent, or we're the uppermost parent
			throw new NotFoundException("Unable to locate a matching ACE for passed permissions and SIDs");
		}
	}

	/**
	 * Compares an ACE Permission to the given Permission. By default, we compare the
	 * Permission masks for exact match. Subclasses of this strategy can override this
	 * behavior and implement more sophisticated comparisons, e.g. a bitwise comparison
	 * for ACEs that grant access. <pre>{@code
	 * if (ace.isGranting() && p.getMask() != 0) {
	 *    return (ace.getPermission().getMask() & p.getMask()) != 0;
	 * } else {
	 *    return ace.getPermission().getMask() == p.getMask();
	 * }
	 * }</pre>
	 * @param ace the ACE from the Acl holding the mask.
	 * @param p the Permission we are checking against.
	 * @return true, if the respective masks are considered to be equal.
	 */
	protected boolean isGranted(AccessControlEntry ace, Permission p) {
		return ace.getPermission().getMask() == p.getMask();
	}

}

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

package org.springframework.security.acls.domain;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.acls.sid.SidRetrievalStrategy;
import org.springframework.security.acls.sid.SidRetrievalStrategyImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.util.Assert;


/**
 * Default implementation of {@link AclAuthorizationStrategy}.
 * <p>
 * Permission will be granted provided the current principal is either the owner (as defined by the ACL), has
 * {@link BasePermission#ADMINISTRATION} (as defined by the ACL and via a {@link Sid} retrieved for the current
 * principal via {@link #sidRetrievalStrategy}), or if the current principal holds the relevant system-wide
 * {@link GrantedAuthority} and injected into the constructor.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclAuthorizationStrategyImpl implements AclAuthorizationStrategy {
    //~ Instance fields ================================================================================================

    private GrantedAuthority gaGeneralChanges;
    private GrantedAuthority gaModifyAuditing;
    private GrantedAuthority gaTakeOwnership;
    private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();

    //~ Constructors ===================================================================================================

    /**
     * Constructor. The only mandatory parameter relates to the system-wide {@link GrantedAuthority} instances that
     * can be held to always permit ACL changes.
     *
     * @param auths an array of <code>GrantedAuthority</code>s that have
     * special permissions (index 0 is the authority needed to change
     * ownership, index 1 is the authority needed to modify auditing details,
     * index 2 is the authority needed to change other ACL and ACE details) (required)
     */
    public AclAuthorizationStrategyImpl(GrantedAuthority[] auths) {
        Assert.isTrue(auths != null && auths.length == 3, "GrantedAuthority[] with three elements required");
        this.gaTakeOwnership = auths[0];
        this.gaModifyAuditing = auths[1];
        this.gaGeneralChanges = auths[2];
    }

    //~ Methods ========================================================================================================

    public void securityCheck(Acl acl, int changeType) {
        if ((SecurityContextHolder.getContext() == null)
            || (SecurityContextHolder.getContext().getAuthentication() == null)
            || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            throw new AccessDeniedException("Authenticated principal required to operate with ACLs");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Check if authorized by virtue of ACL ownership
        Sid currentUser = new PrincipalSid(authentication);

        if (currentUser.equals(acl.getOwner())
                && ((changeType == CHANGE_GENERAL) || (changeType == CHANGE_OWNERSHIP))) {
            return;
        }

        // Not authorized by ACL ownership; try via adminstrative permissions
        GrantedAuthority requiredAuthority = null;

        if (changeType == CHANGE_AUDITING) {
            requiredAuthority = this.gaModifyAuditing;
        } else if (changeType == CHANGE_GENERAL) {
            requiredAuthority = this.gaGeneralChanges;
        } else if (changeType == CHANGE_OWNERSHIP) {
            requiredAuthority = this.gaTakeOwnership;
        } else {
            throw new IllegalArgumentException("Unknown change type");
        }

        // Iterate this principal's authorities to determine right
        List<GrantedAuthority> auths = authentication.getAuthorities();

        for (int i = 0; i < auths.size(); i++) {
            if (requiredAuthority.equals(auths.get(i))) {
                return;
            }
        }

        // Try to get permission via ACEs within the ACL
        List<Sid> sids = sidRetrievalStrategy.getSids(authentication);

        if (acl.isGranted(Arrays.asList(BasePermission.ADMINISTRATION), sids, false)) {
            return;
        }

        throw new AccessDeniedException(
                "Principal does not have required ACL permissions to perform requested operation");
    }

    public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
        Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }
}

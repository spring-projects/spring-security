/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.acl.basic;

import org.springframework.dao.DataAccessException;

/**
 * Represents a more extensive data access object
 * for {@link BasicAclEntry}s.
 * 
 * <P>
 * <code>BasicAclExtendedDao</code> implementations are responsible for interpreting a
 * a given {@link AclObjectIdentity}.
 * </p>
 * 
 * @author Ben Alex
 * @version $Id$
 */
public interface BasicAclExtendedDao extends BasicAclDao {
    //~ Methods ================================================================

	public void create(BasicAclEntry basicAclEntry)  throws DataAccessException;
	
	/**
	 * Deletes <b>all</b> entries associated with the
	 * specified <code>AclObjectIdentity</code>.
	 * 
	 * @param aclObjectIdentity to delete, including any <code>BasicAclEntry</code>s
	 */
	public void delete(AclObjectIdentity aclObjectIdentity) throws DataAccessException;
	
	/**
	 * Deletes the <code>BasicAclEntry</code> associated with the specified
	 * <code>AclObjectIdentity</code> and recipient <code>Object</code>.
	 * 
	 * @param aclObjectIdentity to delete
	 * @param recipient to delete
	 */
	public void delete(AclObjectIdentity aclObjectIdentity, Object recipient) throws DataAccessException;
	
	/**
	 * Changes the permission mask assigned to the <code>BasicAclEntry</code>
	 * associated with the specified
	 * <code>AclObjectIdentity</code> and recipient <code>Object</code>.
	 * 
	 * @param aclObjectIdentity to locate the relevant <code>BasicAclEntry</code>
	 * @param recipient to locate the relevant <code>BasicAclEntry</code>
	 * @param newMask indicating the new permission
	 */
	public void changeMask(AclObjectIdentity aclObjectIdentity, Object recipient, Integer newMask) throws DataAccessException;
}

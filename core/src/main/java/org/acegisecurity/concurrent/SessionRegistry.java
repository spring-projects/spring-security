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

package org.acegisecurity.concurrent;

/**
 * Maintains a registry of <code>SessionInformation</code> instances.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface SessionRegistry {
    //~ Methods ================================================================

    /**
     * Obtains all the known principals in the <code>SessionRegistry</code>.
     *
     * @return each of the unique principals, which can then be presented to
     *         {@link #getAllSessions(Object)}.
     */
    public Object[] getAllPrincipals();

    /**
     * Obtains all the known sessions for the specified principal. Sessions
     * that have expired or destroyed are not returned.
     *
     * @param principal to locate sessions for (should never be
     *        <code>null</code>)
     *
     * @return the unexpired and undestroyed sessions for this principal, or
     *         <code>null</code> if none were found
     */
    public SessionInformation[] getAllSessions(Object principal);

    /**
     * Obtains the session information for the specified
     * <code>sessionId</code>. Even expired sessions are returned (although
     * destroyed sessions are never returned).
     *
     * @param sessionId to lookup (should never be <code>null</code>)
     *
     * @return the session information, or <code>null</code> if not found
     */
    public SessionInformation getSessionInformation(String sessionId);

    /**
     * Updates the given <code>sessionId</code> so its last request time is
     * equal to the present date and time. Silently returns if the given
     * <code>sessionId</code> cannot be found or the session is marked to
     * expire.
     *
     * @param sessionId for which to update the date and time of the last
     *        request (should never be <code>null</code>)
     */
    public void refreshLastRequest(String sessionId);

    /**
     * Registers a new session for the specified principal. The newly
     * registered session will not be marked for expiration.
     *
     * @param sessionId to associate with the principal (should never be
     *        <code>null</code>)
     * @param principal to associate with the session (should never be
     *        <code>null</code>)
     *
     * @throws SessionAlreadyUsedException DOCUMENT ME!
     */
    public void registerNewSession(String sessionId, Object principal)
        throws SessionAlreadyUsedException;

    /**
     * Deletes all the session information being maintained for the specified
     * <code>sessionId</code>. If the <code>sessionId</code> is not found, the
     * method gracefully returns.
     *
     * @param sessionId to delete information for (should never be
     *        <code>null</code>)
     */
    public void removeSessionInformation(String sessionId);
}

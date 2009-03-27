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

package org.springframework.security.cas.authentication;

/**
 * Caches CAS service tickets and CAS proxy tickets for stateless connections.
 *
 * <p>
 * When a service ticket or proxy ticket is validated against the CAS server,
 * it is unable to be used again. Most types of callers are stateful and are
 * associated with a given <code>HttpSession</code>. This allows the
 * affirmative CAS validation outcome to be stored in the
 * <code>HttpSession</code>, meaning the removal of the ticket from the CAS
 * server is not an issue.
 * </p>
 *
 * <P>
 * Stateless callers, such as remoting protocols, cannot take advantage of
 * <code>HttpSession</code>. If the stateless caller is located a significant
 * network distance from the CAS server, acquiring a fresh service ticket or
 * proxy ticket for each invocation would be expensive.
 * </p>
 *
 * <P>
 * To avoid this issue with stateless callers, it is expected stateless callers
 * will obtain a single service ticket or proxy ticket, and then present this
 * same ticket to the Spring Security secured application on each
 * occasion. As no <code>HttpSession</code> is available for such callers, the
 * affirmative CAS validation outcome cannot be stored in this location.
 * </p>
 *
 * <P>
 * The <code>StatelessTicketCache</code> enables the service tickets and proxy
 * tickets belonging to stateless callers to be placed in a cache. This
 * in-memory cache stores the <code>CasAuthenticationToken</code>, effectively
 * providing the same capability as a <code>HttpSession</code> with the ticket
 * identifier being the key rather than a session identifier.
 * </p>
 *
 * <P>
 * Implementations should provide a reasonable timeout on stored entries, such
 * that the stateless caller are not required to unnecessarily acquire fresh
 * CAS service tickets or proxy tickets.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface StatelessTicketCache {
    //~ Methods ================================================================

    /**
     * Retrieves the <code>CasAuthenticationToken</code> associated with the
     * specified ticket.
     *
     * <P>
     * If not found, returns a
     * <code>null</code><code>CasAuthenticationToken</code>.
     * </p>
     *
     * @return the fully populated authentication token
     */
    CasAuthenticationToken getByTicketId(String serviceTicket);

    /**
     * Adds the specified <code>CasAuthenticationToken</code> to the cache.
     *
     * <P>
     * The {@link CasAuthenticationToken#getCredentials()} method is used to
     * retrieve the service ticket number.
     * </p>
     *
     * @param token to be added to the cache
     */
    void putTicketInCache(CasAuthenticationToken token);

    /**
     * Removes the specified ticket from the cache, as per  {@link
     * #removeTicketFromCache(String)}.
     *
     * <P>
     * Implementations should use {@link
     * CasAuthenticationToken#getCredentials()} to obtain the ticket and then
     * delegate to to the  {@link #removeTicketFromCache(String)} method.
     * </p>
     *
     * @param token to be removed
     */
    void removeTicketFromCache(CasAuthenticationToken token);

    /**
     * Removes the specified ticket from the cache, meaning that future calls
     * will require a new service ticket.
     *
     * <P>
     * This is in case applications wish to provide a session termination
     * capability for their stateless clients.
     * </p>
     *
     * @param serviceTicket to be removed
     */
    void removeTicketFromCache(String serviceTicket);
}

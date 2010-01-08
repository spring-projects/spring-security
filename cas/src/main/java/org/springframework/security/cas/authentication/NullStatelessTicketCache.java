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
package org.springframework.security.cas.authentication;


/**
 * Implementation of @link {@link StatelessTicketCache} that has no backing cache.  Useful
 * in instances where storing of tickets for stateless session management is not required.
 * <p>
 * This is the default StatelessTicketCache of the @link {@link CasAuthenticationProvider} to
 * eliminate the unnecessary dependency on EhCache that applications have even if they are not using
 * the stateless session management.
 *
 * @author Scott Battaglia
 *
 *@see CasAuthenticationProvider
 */
public final class NullStatelessTicketCache implements StatelessTicketCache {

    /**
     * @return null since we are not storing any tickets.
     */
    public CasAuthenticationToken getByTicketId(final String serviceTicket) {
        return null;
    }

    /**
     * This is a no-op since we are not storing tickets.
     */
    public void putTicketInCache(final CasAuthenticationToken token) {
        // nothing to do
    }

    /**
     * This is a no-op since we are not storing tickets.
     */
    public void removeTicketFromCache(final CasAuthenticationToken token) {
        // nothing to do
    }

    /**
     * This is a no-op since we are not storing tickets.
     */
    public void removeTicketFromCache(final String serviceTicket) {
        // nothing to do
    }
}

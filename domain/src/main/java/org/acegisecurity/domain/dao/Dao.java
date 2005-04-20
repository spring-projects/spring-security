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

package net.sf.acegisecurity.domain.dao;

import net.sf.acegisecurity.domain.PersistableEntity;

import java.io.Serializable;

import java.util.Collection;
import java.util.List;


/**
 * Provides fundamental DAO capabilities for a single concrete {@link
 * PersistableEntity}.
 * 
 * <P>
 * This interface provides a portable approach to Data Access Object (DAO)
 * functionality across various object relational persistance solutions.
 * </p>
 * 
 * <p>
 * It is not envisioned that this interface will provide <b>all</b> data access
 * requirements for applications, however it should provide all of the
 * standard create, read, update, delete (CRUD) and finder functions that are
 * routinely needed. Specialized subclasses (that provide finer-grained
 * functionality) of the <code>Dao</code> interface are encouraged.
 * </p>
 * 
 * <P>
 * A <code>Dao</code> implementation (or a subclass of <code>Dao</code>) should
 * be the sole entry point into the persistance layer of an application. The
 * persistence layer should only respond to requests from the services layer.
 * The services layer is where all transaction demarcation, security
 * authorization, casting to and from concrete {@link
 * net.sf.acegisecurity.domain.PersistableEntity}s, workflow and business
 * logic should take place.
 * </p>
 * 
 * <p>
 * Each <code>Dao</code> implementation will support one
 * <code>PersistableEntity</code> classes only. The supported
 * <code>PersistableEntity</code> class must be indicated via the {@link
 * #supports(Class)} method.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface Dao {
    //~ Methods ================================================================

    /**
     * Create a new object, with the current {@link
     * PersistableEntity#getInternalId()} value being ignored.
     *
     * @param value (without the identity property initialized)
     *
     * @return the value created (with the identity property initialised)
     */
    public PersistableEntity create(PersistableEntity value);

    /**
     * Saves an existing object to the persistence layer, or creates a new
     * object in the persistence layer. Implementations typically rely on
     * {@link PersistableEntity#getInternalId()} being non-<code>null</code>
     * to differentiate between persistence instances previous saved and those
     * requiring initial creation.
     *
     * @param value to save or update
     *
     * @return the saved or updated (as appropriate) value
     */
    public PersistableEntity createOrUpdate(PersistableEntity value);

    /**
     * Delete an object.
     *
     * @param value the value to delete
     */
    public void delete(PersistableEntity value);

    /**
     * Return all persistent instances, including subclasses.
     *
     * @return all persistence instances (an empty <code>List</code> will be
     *         returned if no matches are found)
     */
    public List findAll();

    /**
     * Find a <code>List</code> of <code>PersistableEntity</code>s, searched by
     * their identifiers.
     *
     * @param ids collection of identifiers to locate
     *
     * @return the values with those identifiers (an empty <code>List</code>
     *         will be returned if no matches are found)
     */
    public List findId(Collection ids);

    /**
     * Load a persistent instance by its identifier.
     *
     * @param id the identifier of the persistent instance desired to be
     *        retrieved
     *
     * @return the request item, or <code>null</code> if not found
     */
    public PersistableEntity readId(Serializable id);

    /**
     * Find persistent instances with properties matching those of the passed
     * <code>PersistableEntity</code>.
     * 
     * <P>
     * Persistent instances are matched on the basis of query by example.
     * Properties whose value is <code>null</code>, empty
     * <code>String</code>s, and any <code>Collection</code>s are ignored in
     * the query by example evaluation.
     * </p>
     *
     * @param value parameters to filter on (the class of this object will be
     *        added to the filter)
     * @param firstElement the first result (start at zero to obtain all
     *        results)
     * @param maxElements the maximum number of results desired for this page
     *        of the result set
     * @param orderByAsc the property name of the
     *        <code>PersistableEntity</code> that should be used to order the
     *        results
     *
     * @return the requested page of the result list (a properly formed
     *         <code>PaginatedList</code> is returned if no results match)
     */
    public PaginatedList scroll(PersistableEntity value, int firstElement,
        int maxElements, String orderByAsc);

    /**
     * Find persistent instances with properties matching those of the passed
     * <code>PersistableEntity</code>, ignoring the class of the passed
     * <code>PersistableEntity</code> (useful if you pass a superclass, as you
     * want to find all subclass instances which match).
     *
     * @param value parameters to filter on (the class of this object will NOT
     *        be added to the filter)
     * @param firstElement the first result (start at zero to obtain all
     *        results)
     * @param maxElements the maximum number of results desired for this page
     *        of the result set
     * @param orderByAsc the property name of the
     *        <code>PersistableEntity</code> that should be used to order the
     *        results
     *
     * @return the requested page of the result list (a properly formed
     *         <code>PaginatedList</code> is returned if no results match)
     */
    public PaginatedList scrollWithSubclasses(PersistableEntity value,
        int firstElement, int maxElements, String orderByAsc);

    /**
     * Indicates whether the DAO instance provides persistence services for the
     * specified class.
     *
     * @param clazz to test, which should be an implementation of
     *        <code>PersistableEntity</code>
     *
     * @return <code>true</code> or <code>false</code>, indicating whether or
     *         not the passed class is supported by this DAO instance
     */
    public boolean supports(Class clazz);

    /**
     * Update an object.
     *
     * @param value to update, with the <code>PersistableEntity</code> having a
     *        non-<code>null</code> identifier
     *
     * @return the updated value
     */
    public PersistableEntity update(PersistableEntity value);
}

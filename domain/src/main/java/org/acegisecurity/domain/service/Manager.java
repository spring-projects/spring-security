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

package net.sf.acegisecurity.domain.service;

import net.sf.acegisecurity.domain.PersistableEntity;
import net.sf.acegisecurity.domain.dao.PaginatedList;

import java.io.Serializable;

import java.util.Collection;
import java.util.List;

/**
 * Provides fundamental services layer capabilities for a single concrete {@link
 * PersistableEntity}, using JDK 1.5 generics.
 * 
 * <P>
 * This interface provides a remoting protocol compliant approach to accessing
 * services layer logic for a given application. A generics-based services
 * layer interface decreases development time because the basic CRUD and finder
 * operations can be specified in a typesafe fashion that reuses superclass
 * code.
 * </p>
 * 
 * <p>
 * It is not envisioned that this interface will provide <b>all</b> services layer
 * functions. The significant value of a services layer is the value-add beyond
 * simply fronting the DAO or applying validation/binding logic that is better
 * situated in the domain object or its validator. The type of value-adds
 * expected to be provided by a services layer include incrementing business
 * identifiers (eg an invoice number); generating messages for logging/audit
 * purposes (thus such messages are at a business transaction level of granularity,
 * instead of DAO/persistence granularity where the overall context of the
 * the message becomes unclear); updating related domain objects via
 * their respective services layer beans (eg an invoice services layer bean
 * would call the general journal services layer bean to create the accrual
 * accounting entries); making changes to a domain object that requires
 * logic that is unsuitable to put into a validator because it extends
 * beyond a single domain object instance or requires access to other persistent
 * entities (eg computing taxation appliable to an invoice based on a break-down
 * of each item on the order, its delivery destination, and the customer);
 * producing messages (eg notify another system the invoice was created or
 * email the customer via SMTP); provide a layer to locate transaction and 
 * security configuration; expose a reasonably protocol-independent interface
 * to the application that can be used by a variety of web services and
 * client types; ensure any returned objects are eagerly loaded to a well-defined
 * interface contract etc.
 * </p>
 * 
 * <P>
 * A single <code>Manager</code> implementation will typically exist for each
 * {@link net.sf.acegisecurity.domain.PersistableEntity}, particularly given
 * a <code>PersistableEntity</code> is allowed to manage multiple
 * {@link net.sf.acegisecurity.domain.impl.PersistableValue}s.
 * The particular <code>PersistableEntity</code> an implementation supports
 * will be expressed by the {@link #supports(Class)} method.
 * </p>
 * 
 * <p>No other part of the Domain subproject relies on this interface. If
 * you would prefer to write your own services layer interfaces from scratch,
 * this is not a problem at all.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public interface Manager<E extends PersistableEntity> {
    //~ Methods ================================================================

    /**
     * Create a new object, with the current {@link
     * PersistableEntity#getInternalId()} value being ignored.
     *
     * @param value (without the identity property initialized)
     *
     * @return the value created (with the identity property initialised)
     */
    public E create(E value);

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
    public E createOrUpdate(E value);

    /**
     * Delete an object.
     *
     * @param value the value to delete
     */
    public void delete(E value);

    /**
     * Return all persistent instances, including subclasses.
     *
     * @return all persistence instances (an empty <code>List</code> will be
     *         returned if no matches are found)
     */
    public List<E> findAll();

    /**
     * Find a <code>List</code> of <code>PersistableEntity</code>s, searched by
     * their identifiers.
     *
     * @param ids collection of identifiers to locate
     *
     * @return the values with those identifiers (an empty <code>List</code>
     *         will be returned if no matches are found)
     */
    public List<E> findId(Collection<Serializable> ids);

    /**
     * Load a persistent instance by its identifier, although some properties
     * may be lazy loaded depending on the underlying DAO implementation and/or
     * persistence engine mapping document.
     *
     * @param id the identifier of the persistent instance desired to be
     *        retrieved
     *
     * @return the request item, or <code>null</code> if not found
     */
    public E readId(Serializable id);

	/**
	 * Loads a persistent instance by its identifier, along with any
	 * lazy loaded properties associated with that instance.
	 * 
     * @param id the identifier of the persistent instance desired to be
     *        retrieved
     *
     * @return the request item, or <code>null</code> if not found
	 */
	public E readPopulatedId(Serializable id);
	
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
     * @param value parameters to filter on (the class of this object will
     * be added to the filter)
     * @param firstElement the first result (start at zero to obtain all
     *        results)
     * @param maxElements the maximum number of results desired for this page
     *        of the result set
     *
     * @return the requested page of the result list (a properly formed
     *         <code>PaginatedList</code> is returned if no results match)
     */
    public PaginatedList<E> scroll(E value, int firstElement,
        int maxElements);

	/**
     * Find persistent instances with properties matching those of the passed
     * <code>PersistableEntity</code>, ignoring the class of the passed
     * <code>PersistableEntity</code> (useful if you pass a superclass, as you
     * want to find all subclass instances which match).
	 * 
     * @param value parameters to filter on (the class of this object will
     * NOT be added to the filter)
     * @param firstElement the first result (start at zero to obtain all
     *        results)
     * @param maxElements the maximum number of results desired for this page
     *        of the result set
     *
     * @return the requested page of the result list (a properly formed
     *         <code>PaginatedList</code> is returned if no results match)
	 */
    public PaginatedList<E> scrollWithSubclasses(E value, int firstElement,
	        int maxElements);

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
    public E update(E value);
}

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

package net.sf.acegisecurity.afterinvocation;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthorizationServiceException;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.acl.AclEntry;
import net.sf.acegisecurity.acl.AclManager;
import net.sf.acegisecurity.acl.basic.AbstractBasicAclEntry;
import net.sf.acegisecurity.acl.basic.SimpleAclEntry;

import org.apache.commons.collections.iterators.ArrayIterator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.lang.reflect.Array;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * <p>
 * Given a <code>Collection</code> of domain object instances returned from a
 * secure object invocation, remove any <code>Collection</code> elements the
 * principal does not have appropriate permission to access as defined by the
 * {@link AclManager}.
 * </p>
 * 
 * <p>
 * The <code>AclManager</code> is used to retrieve the access control list
 * (ACL) permissions associated with each <code>Collection</code>  domain
 * object instance element for the current <code>Authentication</code> object.
 * This class is designed to process {@link AclEntry}s that are subclasses of
 * {@link net.sf.acegisecurity.acl.basic.AbstractBasicAclEntry} only.
 * Generally these are obtained by using the {@link
 * net.sf.acegisecurity.acl.basic.BasicAclProvider}.
 * </p>
 * 
 * <p>
 * This after invocation provider will fire if any {@link
 * ConfigAttribute#getAttribute()} matches the {@link
 * #processConfigAttribute}. The provider will then lookup the ACLs from the
 * <code>AclManager</code> and ensure the principal is {@link
 * net.sf.acegisecurity.acl.basic.AbstractBasicAclEntry#isPermitted(int)} for
 * at least one of the {@link #requirePermission}s for each
 * <code>Collection</code> element. If the principal does not have at least
 * one of the permissions, that element will not be included in the returned
 * <code>Collection</code>.
 * </p>
 * 
 * <p>
 * Often users will setup a <code>BasicAclEntryAfterInvocationProvider</code>
 * with a {@link #processConfigAttribute} of
 * <code>AFTER_ACL_COLLECTION_READ</code> and a {@link #requirePermission} of
 * <code>SimpleAclEntry.READ</code>. These are also the defaults.
 * </p>
 * 
 * <p>
 * The <code>AclManager</code> is allowed to return any implementations of
 * <code>AclEntry</code> it wishes. However, this provider will only be able
 * to validate against <code>AbstractBasicAclEntry</code>s, and thus a
 * <code>Collection</code> element will be filtered from the resulting
 * <code>Collection</code> if no <code>AclEntry</code> is of type
 * <code>AbstractBasicAclEntry</code>.
 * </p>
 * 
 * <p>
 * If the provided <code>returnObject</code> is <code>null</code>, a
 * <code>null</code><code>Collection</code> will be returned. If the provided
 * <code>returnObject</code> is not a <code>Collection</code>, an {@link
 * AuthorizationServiceException} will be thrown.
 * </p>
 * 
 * <p>
 * All comparisons and prefixes are case sensitive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclEntryAfterInvocationCollectionFilteringProvider
    implements AfterInvocationProvider, InitializingBean {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(BasicAclEntryAfterInvocationCollectionFilteringProvider.class);

    //~ Instance fields ========================================================

    private AclManager aclManager;
    private String processConfigAttribute = "AFTER_ACL_COLLECTION_READ";
    private int[] requirePermission = {SimpleAclEntry.READ};

    //~ Methods ================================================================

    public void setAclManager(AclManager aclManager) {
        this.aclManager = aclManager;
    }

    public AclManager getAclManager() {
        return aclManager;
    }

    public void setProcessConfigAttribute(String processConfigAttribute) {
        this.processConfigAttribute = processConfigAttribute;
    }

    public String getProcessConfigAttribute() {
        return processConfigAttribute;
    }

    public void setRequirePermission(int[] requirePermission) {
        this.requirePermission = requirePermission;
    }

    public int[] getRequirePermission() {
        return requirePermission;
    }

    public void afterPropertiesSet() throws Exception {
        if (processConfigAttribute == null) {
            throw new IllegalArgumentException(
                "A processConfigAttribute is mandatory");
        }

        if ((requirePermission == null) || (requirePermission.length == 0)) {
            throw new IllegalArgumentException(
                "One or more requirePermission entries is mandatory");
        }

        if (aclManager == null) {
            throw new IllegalArgumentException("An aclManager is mandatory");
        }
    }

    public Object decide(Authentication authentication, Object object,
        ConfigAttributeDefinition config, Object returnedObject)
        throws AccessDeniedException {
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) iter.next();

            if (this.supports(attr)) {
                // Need to process the Collection for this invocation
                if (returnedObject == null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Return object is null, skipping");
                    }

                    return null;
                }

                Filterer filterer = null;

                if (returnedObject instanceof Collection) {
                    Collection collection = (Collection) returnedObject;
                    filterer = new CollectionFilterer(collection);
                } else if (returnedObject.getClass().isArray()) {
                    Object[] array = (Object[]) returnedObject;
                    filterer = new ArrayFilterer(array);
                } else {
                    throw new AuthorizationServiceException(
                        "A Collection or an array (or null) was required as the returnedObject, but the returnedObject was: "
                        + returnedObject);
                }

                // Locate unauthorised Collection elements
                Iterator collectionIter = filterer.iterator();

                while (collectionIter.hasNext()) {
                    Object domainObject = collectionIter.next();

                    boolean hasPermission = false;

                    AclEntry[] acls = null;

                    if (domainObject == null) {
                        hasPermission = true;
                    } else {
                        acls = aclManager.getAcls(domainObject, authentication);
                    }

                    if ((acls != null) && (acls.length != 0)) {
                        for (int i = 0; i < acls.length; i++) {
                            // Locate processable AclEntrys
                            if (acls[i] instanceof AbstractBasicAclEntry) {
                                AbstractBasicAclEntry processableAcl = (AbstractBasicAclEntry) acls[i];

                                // See if principal has any of the required permissions
                                for (int y = 0; y < requirePermission.length;
                                    y++) {
                                    if (processableAcl.isPermitted(
                                            requirePermission[y])) {
                                        hasPermission = true;

                                        if (logger.isDebugEnabled()) {
                                            logger.debug(
                                                "Principal is authorised for element: "
                                                + domainObject
                                                + " due to ACL: "
                                                + processableAcl.toString());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (!hasPermission) {
                        filterer.remove(domainObject);

                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "Principal is NOT authorised for element: "
                                + domainObject);
                        }
                    }
                }

                return filterer.getFilteredObject();
            }
        }

        return returnedObject;
    }

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null)
            && attribute.getAttribute().equals(getProcessConfigAttribute())) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * This implementation supports any type of class, because it does not
     * query the presented secure object.
     *
     * @param clazz the secure object
     *
     * @return always <code>true</code>
     */
    public boolean supports(Class clazz) {
        return true;
    }
}


/**
 * Filter strategy interface.
 */
interface Filterer {
    //~ Methods ================================================================

    /**
     * Gets the filtered collection or array.
     *
     * @return the filtered collection or array
     */
    public Object getFilteredObject();

    /**
     * Returns an iterator over the filtered collection or array.
     *
     * @return an Iterator
     */
    public Iterator iterator();

    /**
     * Removes the the given object from the resulting list.
     *
     * @param object the object to be removed
     */
    public void remove(Object object);
}


/**
 * A filter used to filter Collections.
 */
class CollectionFilterer implements Filterer {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(BasicAclEntryAfterInvocationCollectionFilteringProvider.class);

    //~ Instance fields ========================================================

    private Collection collection;
    private Set removeList;

    //~ Constructors ===========================================================

    CollectionFilterer(Collection collection) {
        this.collection = collection;

        // We create a Set of objects to be removed from the Collection,
        // as ConcurrentModificationException prevents removal during
        // iteration, and making a new Collection to be returned is
        // problematic as the original Collection implementation passed
        // to the method may not necessarily be re-constructable (as
        // the Collection(collection) constructor is not guaranteed and
        // manually adding may lose sort order or other capabilities)
        removeList = new HashSet();
    }

    //~ Methods ================================================================

    /**
     * @see net.sf.acegisecurity.afterinvocation.Filterer#getFilteredObject()
     */
    public Object getFilteredObject() {
        // Now the Iterator has ended, remove Objects from Collection
        Iterator removeIter = removeList.iterator();

        int originalSize = collection.size();

        while (removeIter.hasNext()) {
            collection.remove(removeIter.next());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Original collection contained " + originalSize
                + " elements; now contains " + collection.size() + " elements");
        }

        return collection;
    }

    /**
     * @see net.sf.acegisecurity.afterinvocation.Filterer#iterator()
     */
    public Iterator iterator() {
        return collection.iterator();
    }

    /**
     * @see net.sf.acegisecurity.afterinvocation.Filterer#remove(java.lang.Object)
     */
    public void remove(Object object) {
        removeList.add(object);
    }
}


/**
 * A filter used to filter arrays.
 */
class ArrayFilterer implements Filterer {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(BasicAclEntryAfterInvocationCollectionFilteringProvider.class);

    //~ Instance fields ========================================================

    private Set removeList;
    private Object[] list;

    //~ Constructors ===========================================================

    ArrayFilterer(Object[] list) {
        this.list = list;

        // Collect the removed objects to a HashSet so that
        // it is fast to lookup them when a filtered array
        // is constructed.
        removeList = new HashSet();
    }

    //~ Methods ================================================================

    /**
     * @see net.sf.acegisecurity.afterinvocation.Filterer#getFilteredObject()
     */
    public Object getFilteredObject() {
        // Recreate an array of same type and filter the removed objects.
        int originalSize = list.length;
        int sizeOfResultingList = originalSize - removeList.size();
        Object[] filtered = (Object[]) Array.newInstance(list.getClass()
                                                             .getComponentType(),
                sizeOfResultingList);

        for (int i = 0, j = 0; i < list.length; i++) {
            Object object = list[i];

            if (!removeList.contains(object)) {
                filtered[j] = object;
                j++;
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Original array contained " + originalSize
                + " elements; now contains " + sizeOfResultingList
                + " elements");
        }

        return filtered;
    }

    /**
     * @see net.sf.acegisecurity.afterinvocation.Filterer#iterator()
     */
    public Iterator iterator() {
        return new ArrayIterator(list);
    }

    /**
     * @see net.sf.acegisecurity.afterinvocation.Filterer#remove(java.lang.Object)
     */
    public void remove(Object object) {
        removeList.add(object);
    }
}

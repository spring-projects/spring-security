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

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.acl.AclEntry;
import net.sf.acegisecurity.acl.AclProvider;
import net.sf.acegisecurity.acl.basic.cache.NullAclEntryCache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.lang.reflect.Constructor;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;


/**
 * <P>
 * Retrieves access control lists (ACL) entries for domain object instances
 * from a data access object (DAO).
 * </p>
 * 
 * <P>
 * This implementation will provide ACL lookup services for any object that it
 * can determine the {@link AclObjectIdentity} for by calling the {@link
 * #obtainIdentity(Object)} method. Subclasses can override this method if
 * they only want the <code>BasicAclProvider</code> responding to particular
 * domain object instances.
 * </p>
 * 
 * <P>
 * <code>BasicAclProvider</code> will walk an inheritance hierarchy if a
 * <code>BasicAclEntry</code> returned by the DAO indicates it has a parent.
 * NB: inheritance occurs at a <I>domain instance object</I> level. It does
 * not occur at an ACL recipient level. This means
 * <B>all</B><code>BasicAclEntry</code>s for a given domain instance object
 * <B>must</B> have the <B>same</B> parent identity, or
 * <B>all</B><code>BasicAclEntry</code>s must have <code>null</code> as their
 * parent identity.
 * </p>
 * 
 * <P>
 * A cache should be used. This is provided by the {@link BasicAclEntryCache}.
 * <code>BasicAclProvider</code> by default is setup to use the {@link
 * NullAclEntryCache}, which performs no caching.
 * </p>
 * 
 * <P>
 * To implement the {@link #getAcls(Object, Authentication)} method,
 * <code>BasicAclProvider</code> requires a {@link EffectiveAclsResolver} to
 * be configured against it. By default the {@link
 * GrantedAuthorityEffectiveAclsResolver} is used.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclProvider implements AclProvider, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(BasicAclProvider.class);

    /**
     * Marker added to the cache to indicate an AclObjectIdentity has no
     * corresponding BasicAclEntry[]s
     */
    private static String RECIPIENT_FOR_CACHE_EMPTY = "RESERVED_RECIPIENT_NOBODY";

    //~ Instance fields ========================================================

    /**
     * Must be set to an appropriate data access object. Defaults to
     * <code>null</code>.
     */
    private BasicAclDao basicAclDao;
    private BasicAclEntryCache basicAclEntryCache = new NullAclEntryCache();
    private Class defaultAclObjectIdentityClass = NamedEntityObjectIdentity.class;
    private Class restrictSupportToClass = null;
    private EffectiveAclsResolver effectiveAclsResolver = new GrantedAuthorityEffectiveAclsResolver();

    //~ Methods ================================================================

    public AclEntry[] getAcls(Object domainInstance) {
        Map map = new HashMap();

        AclObjectIdentity aclIdentity = obtainIdentity(domainInstance);

        if (aclIdentity == null) {
            throw new IllegalArgumentException(
                "domainInstance is not supported by this provider");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Looking up: " + aclIdentity.toString());
        }

        BasicAclEntry[] instanceAclEntries = lookup(aclIdentity);

        // Exit if there is no ACL information or parent for this instance
        if (instanceAclEntries == null) {
            return null;
        }

        // Add the leaf objects to the Map, keyed on recipient
        for (int i = 0; i < instanceAclEntries.length; i++) {
            if (logger.isDebugEnabled()) {
                logger.debug("Explicit add: "
                    + instanceAclEntries[i].toString());
            }

            map.put(instanceAclEntries[i].getRecipient(), instanceAclEntries[i]);
        }

        AclObjectIdentity parent = instanceAclEntries[0]
            .getAclObjectParentIdentity();

        while (parent != null) {
            BasicAclEntry[] parentAclEntries = lookup(parent);

            if (logger.isDebugEnabled()) {
                logger.debug("Parent lookup: " + parent.toString());
            }

            // Exit loop if parent couldn't be found (unexpected condition)
            if (parentAclEntries == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Parent could not be found in ACL repository");
                }

                break;
            }

            // Now add each _NEW_ recipient to the list
            for (int i = 0; i < parentAclEntries.length; i++) {
                if (!map.containsKey(parentAclEntries[i].getRecipient())) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Added parent to map: "
                            + parentAclEntries[i].toString());
                    }

                    map.put(parentAclEntries[i].getRecipient(),
                        parentAclEntries[i]);
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Did NOT add parent to map: "
                            + parentAclEntries[i].toString());
                    }
                }
            }

            // Prepare for next iteration of while loop
            parent = parentAclEntries[0].getAclObjectParentIdentity();
        }

        Collection collection = map.values();

        return (AclEntry[]) collection.toArray(new AclEntry[] {});
    }

    public AclEntry[] getAcls(Object domainInstance,
        Authentication authentication) {
        AclEntry[] allAcls = (AclEntry[]) this.getAcls(domainInstance);

        return this.effectiveAclsResolver.resolveEffectiveAcls(allAcls,
            authentication);
    }

    public void setBasicAclDao(BasicAclDao basicAclDao) {
        this.basicAclDao = basicAclDao;
    }

    public BasicAclDao getBasicAclDao() {
        return basicAclDao;
    }

    public void setBasicAclEntryCache(BasicAclEntryCache basicAclEntryCache) {
        this.basicAclEntryCache = basicAclEntryCache;
    }

    public BasicAclEntryCache getBasicAclEntryCache() {
        return basicAclEntryCache;
    }

    /**
     * Allows selection of the <code>AclObjectIdentity</code> class that an
     * attempt should be made to construct if the passed object does not
     * implement <code>AclObjectIdentityAware</code>.
     * 
     * <P>
     * NB: Any <code>defaultAclObjectIdentityClass</code><b>must</b> provide a
     * public constructor that accepts an <code>Object</code>. Otherwise it is
     * not possible for the <code>BasicAclProvider</code> to try to create the
     * <code>AclObjectIdentity</code> instance at runtime.
     * </p>
     *
     * @param defaultAclObjectIdentityClass
     */
    public void setDefaultAclObjectIdentityClass(
        Class defaultAclObjectIdentityClass) {
        this.defaultAclObjectIdentityClass = defaultAclObjectIdentityClass;
    }

    public Class getDefaultAclObjectIdentityClass() {
        return defaultAclObjectIdentityClass;
    }

    public void setEffectiveAclsResolver(
        EffectiveAclsResolver effectiveAclsResolver) {
        this.effectiveAclsResolver = effectiveAclsResolver;
    }

    public EffectiveAclsResolver getEffectiveAclsResolver() {
        return effectiveAclsResolver;
    }

    /**
     * If set to a value other than <code>null</code>, the {@link
     * #supports(Object)} method will <b>only</b> support the indicates class.
     * This is useful if you wish to wire multiple
     * <code>BasicAclProvider</code>s in a list of
     * <code>AclProviderManager.providers</code> but only have particular
     * instances respond to particular domain object types.
     *
     * @param restrictSupportToClass the class to restrict this
     *        <code>BasicAclProvider</code> to service request for, or
     *        <code>null</code> (the default) if the
     *        <code>BasicAclProvider</code> should respond to every class
     *        presented
     */
    public void setRestrictSupportToClass(Class restrictSupportToClass) {
        this.restrictSupportToClass = restrictSupportToClass;
    }

    public Class getRestrictSupportToClass() {
        return restrictSupportToClass;
    }

    public void afterPropertiesSet() {
        if (basicAclDao == null) {
            throw new IllegalArgumentException("basicAclDao required");
        }

        if (basicAclEntryCache == null) {
            throw new IllegalArgumentException("basicAclEntryCache required");
        }

        if (effectiveAclsResolver == null) {
            throw new IllegalArgumentException("effectiveAclsResolver required");
        }

        if ((defaultAclObjectIdentityClass == null)
            || (!AclObjectIdentity.class.isAssignableFrom(
                this.defaultAclObjectIdentityClass))) {
            throw new IllegalArgumentException(
                "defaultAclObjectIdentityClass that implements AclObjectIdentity is required");
        }

        try {
            Constructor constructor = defaultAclObjectIdentityClass
                .getConstructor(new Class[] {Object.class});
        } catch (NoSuchMethodException nsme) {
            throw new IllegalArgumentException(
                "defaultAclObjectIdentityClass must provide a constructor that accepts the domain object instance!");
        }
    }

    /**
     * Indicates support for the passed object.
     * 
     * <p>
     * An object will only be supported if it (i) is allowed to be supported as
     * defined by the {@link #setRestrictSupportToClass(Class)} method,
     * <b>and</b> (ii) if an <code>AclObjectIdentity</code> is returned by
     * {@link #obtainIdentity(Object)} for that object.
     * </p>
     *
     * @param domainInstance the instance to check
     *
     * @return <code>true</code> if this provider supports the passed object,
     *         <code>false</code> otherwise
     */
    public boolean supports(Object domainInstance) {
        if (domainInstance == null) {
            return false;
        }

        if ((restrictSupportToClass != null)
            && !restrictSupportToClass.isAssignableFrom(
                domainInstance.getClass())) {
            return false;
        }

        if (obtainIdentity(domainInstance) == null) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * This method looks up the <code>AclObjectIdentity</code> of a passed
     * domain object instance.
     * 
     * <P>
     * This implementation attempts to obtain the
     * <code>AclObjectIdentity</code> via reflection inspection of the class
     * for the {@link AclObjectIdentityAware} interface. If this fails, an
     * attempt is made to construct a {@link
     * #getDefaultAclObjectIdentityClass()} object by passing the domain
     * instance object into its constructor.
     * </p>
     *
     * @param domainInstance the domain object instance (never
     *        <code>null</code>)
     *
     * @return an ACL object identity, or <code>null</code> if one could not be
     *         obtained
     */
    protected AclObjectIdentity obtainIdentity(Object domainInstance) {
        if (domainInstance instanceof AclObjectIdentityAware) {
            AclObjectIdentityAware aclObjectIdentityAware = (AclObjectIdentityAware) domainInstance;

            return aclObjectIdentityAware.getAclObjectIdentity();
        }

        try {
            Constructor constructor = defaultAclObjectIdentityClass
                .getConstructor(new Class[] {Object.class});

            return (AclObjectIdentity) constructor.newInstance(new Object[] {domainInstance});
        } catch (Exception ex) {
            return null;
        }
    }

    private BasicAclEntry[] lookup(AclObjectIdentity aclObjectIdentity) {
        BasicAclEntry[] result = basicAclEntryCache.getEntriesFromCache(aclObjectIdentity);

        if (result != null) {
            if (result[0].getRecipient().equals(RECIPIENT_FOR_CACHE_EMPTY)) {
                return null;
            } else {
                return result;
            }
        }

        result = basicAclDao.getAcls(aclObjectIdentity);

        if (result == null) {
            SimpleAclEntry[] emptyAclEntries = {new SimpleAclEntry(RECIPIENT_FOR_CACHE_EMPTY,
                        aclObjectIdentity, null, 0)};
            basicAclEntryCache.putEntriesInCache(emptyAclEntries);

            return null;
        }

        basicAclEntryCache.putEntriesInCache(result);

        return result;
    }
}

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

package org.acegisecurity.domain.validation;

import org.acegisecurity.domain.dao.DetachmentContextHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import org.springframework.validation.BindException;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 * Default implementation of {@link ValidationManager}.
 *
 * @author Ben Alex
 * @author Matthew E. Porter
 * @version $Id$
 */
public class ValidationManagerImpl implements InitializingBean,
    ValidationManager {
    //~ Instance fields ========================================================

    protected final Log logger = LogFactory.getLog(getClass());
    private IntrospectionManager introspectionManager;
    private ValidationRegistryManager validationRegistryManager = new ValidationRegistryManagerImpl();
    private boolean strictValidation = true;

    //~ Methods ================================================================

    public void setIntrospectionManager(
        IntrospectionManager introspectionManager) {
        this.introspectionManager = introspectionManager;
    }

    public IntrospectionManager getIntrospectionManager() {
        return introspectionManager;
    }

    /**
     * Indicates whether a {@link ValidatorNotFoundException} should be thrown
     * if any domain object does not have a corresponding
     * <code>Validator</code>.
     * 
     * <p>
     * Defaults to <code>true</code>. This is a reasonable default, as callers
     * of <code>ValidationManager</code> should expect the object to support
     * validation.
     * </p>
     *
     * @param strictValidation set to <code>false</code> if you wish to
     *        silently ignore any domain object that is missing a
     *        <code>Validator</code>
     */
    public void setStrictValidation(boolean strictValidation) {
        this.strictValidation = strictValidation;
    }

    public boolean isStrictValidation() {
        return strictValidation;
    }

    public void setValidationRegistryManager(
        ValidationRegistryManager validationRegistryManager) {
        this.validationRegistryManager = validationRegistryManager;
    }

    public ValidationRegistryManager getValidationRegistryManager() {
        return validationRegistryManager;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(validationRegistryManager,
            "A ValidationRegistryManager is required");
        Assert.notNull(introspectionManager,
            "An IntrospectionManager is required");
    }

    /**
     * Validates the passed domain object, along with any children,
     * grandchildren, great-grandchildren etc.
     *
     * @param domainObject to validate (cannot be <code>null</code>)
     *
     * @throws BindException if a validation problem occurs
     * @throws ValidatorNotFoundException if no matching <code>Validator</code>
     *         could be found for the object or its children (only ever thrown
     *         if the {@link #strictValidation}) was set to
     *         <code>true</code>).
     */
    public void validate(Object domainObject)
        throws BindException, ValidatorNotFoundException {
        // Abort if null
        Assert.notNull(domainObject,
            "Cannot validate a null domain object, as unable to getClass()");

        // Construct a list of objects to be validated and adds self
        List<Object> allObjects = new Vector<Object>();
        allObjects.add(domainObject);

        // Add all children (and grandchildren, great-grandchildren etc)
        // of domain object to the list of objects to be validated
        // (list never contains null)
        obtainAllChildren(domainObject, allObjects);

        Assert.notEmpty(allObjects,
            "The list of objects to be validated was empty");

        // Process list of objects to be validated by validating each
        Iterator<Object> iter = allObjects.iterator();

        while (iter.hasNext()) {
            Object currentDomainObject = iter.next();
            Class clazz = currentDomainObject.getClass();

            DetachmentContextHolder.setForceReturnOfDetachedInstances(true);
            try {
                // Call bindSupport() if this class wishes
                BindBeforeValidationUtils.bindIfRequired(currentDomainObject);

                Errors errors = new BindException(currentDomainObject,
                        clazz.getName());
                Validator v = findValidator(clazz);

                // Perform validation
                v.validate(currentDomainObject, errors);

                // Handle validation outcome
                if (errors.getErrorCount() == 0) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Validated '" + clazz + "' successfully using '"
							+ v.getClass() + "'");
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Validated '" + clazz + "' using '" + v.getClass()
                            + "' but errors detected");
                    }

                    throw (BindException) errors;
                }
            } catch (ValidatorNotFoundException validatorNotFoundException) {
                if (strictValidation) {
                    if (logger.isErrorEnabled()) {
                        logger.error(validatorNotFoundException);
                    }

                    throw validatorNotFoundException;
                }

                if (logger.isDebugEnabled()) {
                    logger.debug("Could not locate validator for class '"
                        + clazz + "'; skipping without error");
                }
            } finally {
            	DetachmentContextHolder.setForceReturnOfDetachedInstances(false);
            }
        }
    }

    private Validator findValidator(Class clazz)
        throws ValidatorNotFoundException {
        Assert.notNull(clazz, "Class cannot be null");

        Validator validator = this.validationRegistryManager.findValidator(clazz);

        if (validator == null) {
            throw new ValidatorNotFoundException(
                "No Validator found for class '" + clazz + "'");
        }

        return validator;
    }

    /**
     * Locates all immediate children of the passed <code>parentObject</code>,
     * adding each of those immediate children to the <code>allObjects</code>
     * list and then calling this same method for each of those immediate
     * children.
     * 
     * <p>
     * Does <b>not</b> add the passed <code>parentObject</code> to the
     * <code>allObjects</code> list. The caller of this method should ensure
     * the <code>parentObject</code> is added to the list instead.
     * </p>
     *
     * @param parentObject the object we wish to locate all children for
     * @param allObjects the list to add the located children to
     */
    private void obtainAllChildren(Object parentObject, List<Object> allObjects) {
        Assert.notNull(parentObject, "Violation of parentObject method contract");
        Assert.notNull(allObjects, "Violation of allObjects method contract");
        Assert.isTrue(allObjects.contains(parentObject),
            "List of objects missing the requested parentObject");

		if (logger.isDebugEnabled()) {
			logger.debug("Searching for children of " + parentObject);
		}
		
        // Add immediate children of this domain object
        List<Object> currentChildren = new Vector<Object>();
        introspectionManager.obtainImmediateChildren(parentObject,
            currentChildren);

        // Now iterate the children, adding their children to the object list
        Iterator<Object> childrenIter = currentChildren.iterator();

        while (childrenIter.hasNext()) {
            Object childObject = childrenIter.next();

            if (childObject != null) {
				if (allObjects.contains(childObject)) {
					if (logger.isDebugEnabled()) {
						logger.debug("Already processed this object (will not re-add): " + childObject);
					}
				} else {
					if (logger.isDebugEnabled()) {
						logger.debug("New child object found; adding child object to list of objects, and searching for its children: " + childObject);
					}
					allObjects.add(childObject);
	                obtainAllChildren(childObject, allObjects);
				}
            }
        }
    }
}

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

package net.sf.acegisecurity.domain.validation;

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
 * @version $Id$
 */
public class ValidationManagerImpl implements InitializingBean,
    ValidationManager {
    //~ Instance fields ========================================================

    protected final Log logger = LogFactory.getLog(getClass());
    private IntrospectionManager introspectionManager;
    private List validators;
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
     * <code>Validator</code> defined against the {@link #validators}.
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

    /**
     * Sets the {@link Validator} objects to be used.
     *
     * @param newList that should be used for validation.
     */
    public void setValidators(List newList) {
        Assert.notNull(newList, "A list of Validators is required");
        Assert.isTrue(newList.size() > 0,
            "At least one Validator must be defined");

        Iterator iter = newList.iterator();

        while (iter.hasNext()) {
            Object currentObject = null;
            currentObject = iter.next();
            Assert.isInstanceOf(Validator.class, currentObject,
                "Validator '" + currentObject
                + "' must be an instance of Validator");
        }

        this.validators = newList;
    }

    public List getValidators() {
        return this.validators;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(validators, "A list of Validators is required");
        Assert.isTrue(validators.size() > 0,
            "At least one Validator must be defined");
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

        // Construct a list of objects to be validated and add self
        List allObjects = new Vector();
        allObjects.add(domainObject);

        // Add all children (and grandchildren, great-grandchildren etc)
        // of domain object to the list of objects to be validated
        // (list never contains null)
        obtainAllChildren(domainObject, allObjects);

        Assert.notEmpty(allObjects,
            "The list of objects to be validated was empty");

        // Process list of objects to be validated by validating each
        Iterator iter = allObjects.iterator();

        while (iter.hasNext()) {
            Object currentDomainObject = iter.next();
            Class clazz = currentDomainObject.getClass();

            try {
                Errors errors = new BindException(currentDomainObject,
                        clazz.getName());
                Validator v = findValidator(clazz);

                // Call bindSupport() if this class wishes
                BindBeforeValidationUtils.bindIfRequired(currentDomainObject);

                // Perform validation
                v.validate(currentDomainObject, errors);

                // Handle validation outcome
                if (errors.getErrorCount() == 0) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Validated '" + clazz + "' successfully");
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Validated '" + clazz
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
            }
        }
    }

    private Validator findValidator(Class clazz)
        throws ValidatorNotFoundException {
        Assert.notNull(clazz, "Class cannot be null");

        Iterator iter = validators.iterator();

        while (iter.hasNext()) {
            Validator validator = (Validator) iter.next();

            if (validator.supports(clazz)) {
                return validator;
            }
        }

        throw new ValidatorNotFoundException("No Validator found for class '"
            + clazz + "'");
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
    private void obtainAllChildren(Object parentObject, List allObjects) {
        Assert.notNull(parentObject, "Violation of parentObject method contract");
        Assert.notNull(allObjects, "Violation of allObjects method contract");
        Assert.isTrue(allObjects.contains(parentObject),
            "List of objects missing the requested parentObject");

        // Add immediate children of this domain object
        List currentChildren = new Vector();
        introspectionManager.obtainImmediateChildren(parentObject,
            currentChildren);

        // Add the children
        allObjects.addAll(currentChildren);

        // Now iterate the children, adding their children to the object list
        Iterator childrenIter = currentChildren.iterator();

        while (childrenIter.hasNext()) {
            Object childObject = childrenIter.next();

            if (childObject != null) {
                obtainAllChildren(childObject, allObjects);
            }
        }
    }
}

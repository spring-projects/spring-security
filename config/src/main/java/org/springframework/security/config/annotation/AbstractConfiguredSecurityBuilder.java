/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * <p>
 * A base {@link SecurityBuilder} that allows {@link SecurityConfigurer} to be applied to
 * it. This makes modifying the {@link SecurityBuilder} a strategy that can be customized
 * and broken up into a number of {@link SecurityConfigurer} objects that have more
 * specific goals than that of the {@link SecurityBuilder}.
 * </p>
 *
 * <p>
 * For example, a {@link SecurityBuilder} may build an {@link DelegatingFilterProxy}, but
 * a {@link SecurityConfigurer} might populate the {@link SecurityBuilder} with the
 * filters necessary for session management, form based login, authorization, etc.
 * </p>
 *
 * @see WebSecurity
 *
 * @author Rob Winch
 *
 * @param <O> The object that this builder returns
 * @param <B> The type of this builder (that is returned by the base class)
 */
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>>
		extends AbstractSecurityBuilder<O> {
	private final Log logger = LogFactory.getLog(getClass());

	private final LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>> configurers = new LinkedHashMap<>();
	private final List<SecurityConfigurer<O, B>> configurersAddedInInitializing = new ArrayList<>();

	private final Map<Class<? extends Object>, Object> sharedObjects = new HashMap<>();

	private final boolean allowConfigurersOfSameType;

	private BuildState buildState = BuildState.UNBUILT;

	private ObjectPostProcessor<Object> objectPostProcessor;

	/***
	 * Creates a new instance with the provided {@link ObjectPostProcessor}. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 */
	protected AbstractConfiguredSecurityBuilder(
			ObjectPostProcessor<Object> objectPostProcessor) {
		this(objectPostProcessor, false);
	}

	/***
	 * Creates a new instance with the provided {@link ObjectPostProcessor}. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 * @param allowConfigurersOfSameType if true, will not override other
	 * {@link SecurityConfigurer}'s when performing apply
	 */
	protected AbstractConfiguredSecurityBuilder(
			ObjectPostProcessor<Object> objectPostProcessor,
			boolean allowConfigurersOfSameType) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		this.allowConfigurersOfSameType = allowConfigurersOfSameType;
	}

	/**
	 * Similar to {@link #build()} and {@link #getObject()} but checks the state to
	 * determine if {@link #build()} needs to be called first.
	 *
	 * @return the result of {@link #build()} or {@link #getObject()}. If an error occurs
	 * while building, returns null.
	 */
	public O getOrBuild() {
		if (isUnbuilt()) {
			try {
				return build();
			}
			catch (Exception e) {
				logger.debug("Failed to perform build. Returning null", e);
				return null;
			}
		}
		else {
			return getObject();
		}
	}

	/**
	 * Applies a {@link SecurityConfigurerAdapter} to this {@link SecurityBuilder} and
	 * invokes {@link SecurityConfigurerAdapter#setBuilder(SecurityBuilder)}.
	 *
	 * @param configurer
	 * @return the {@link SecurityConfigurerAdapter} for further customizations
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer)
			throws Exception {
		configurer.addObjectPostProcessor(objectPostProcessor);
		configurer.setBuilder((B) this);
		add(configurer);
		return configurer;
	}

	/**
	 * Applies a {@link SecurityConfigurer} to this {@link SecurityBuilder} overriding any
	 * {@link SecurityConfigurer} of the exact same class. Note that object hierarchies
	 * are not considered.
	 *
	 * @param configurer
	 * @return the {@link SecurityConfigurerAdapter} for further customizations
	 * @throws Exception
	 */
	public <C extends SecurityConfigurer<O, B>> C apply(C configurer) throws Exception {
		add(configurer);
		return configurer;
	}

	/**
	 * Sets an object that is shared by multiple {@link SecurityConfigurer}.
	 *
	 * @param sharedType the Class to key the shared object by.
	 * @param object the Object to store
	 */
	@SuppressWarnings("unchecked")
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		this.sharedObjects.put(sharedType, object);
	}

	/**
	 * Gets a shared Object. Note that object heirarchies are not considered.
	 *
	 * @param sharedType the type of the shared Object
	 * @return the shared Object or null if it is not found
	 */
	@SuppressWarnings("unchecked")
	public <C> C getSharedObject(Class<C> sharedType) {
		return (C) this.sharedObjects.get(sharedType);
	}

	/**
	 * Gets the shared objects
	 * @return the shared Objects
	 */
	public Map<Class<? extends Object>, Object> getSharedObjects() {
		return Collections.unmodifiableMap(this.sharedObjects);
	}

	/**
	 * Adds {@link SecurityConfigurer} ensuring that it is allowed and invoking
	 * {@link SecurityConfigurer#init(SecurityBuilder)} immediately if necessary.
	 *
	 * @param configurer the {@link SecurityConfigurer} to add
	 * @throws Exception if an error occurs
	 */
	@SuppressWarnings("unchecked")
	private <C extends SecurityConfigurer<O, B>> void add(C configurer) throws Exception {
		Assert.notNull(configurer, "configurer cannot be null");

		Class<? extends SecurityConfigurer<O, B>> clazz = (Class<? extends SecurityConfigurer<O, B>>) configurer
				.getClass();
		synchronized (configurers) {
			if (buildState.isConfigured()) {
				throw new IllegalStateException("Cannot apply " + configurer
						+ " to already built object");
			}
			List<SecurityConfigurer<O, B>> configs = allowConfigurersOfSameType ? this.configurers
					.get(clazz) : null;
			if (configs == null) {
				configs = new ArrayList<>(1);
			}
			configs.add(configurer);
			this.configurers.put(clazz, configs);
			if (buildState.isInitializing()) {
				this.configurersAddedInInitializing.add(configurer);
			}
		}
	}

	/**
	 * Gets all the {@link SecurityConfigurer} instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the {@link SecurityConfigurer} class to look for
	 * @return a list of {@link SecurityConfigurer}s for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> getConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.get(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Removes all the {@link SecurityConfigurer} instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the {@link SecurityConfigurer} class to look for
	 * @return a list of {@link SecurityConfigurer}s for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> removeConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.remove(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Gets the {@link SecurityConfigurer} by its class name or <code>null</code> if not
	 * found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return the {@link SecurityConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C getConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.get(clazz);
		if (configs == null) {
			return null;
		}
		if (configs.size() != 1) {
			throw new IllegalStateException("Only one configurer expected for type "
					+ clazz + ", but got " + configs);
		}
		return (C) configs.get(0);
	}

	/**
	 * Removes and returns the {@link SecurityConfigurer} by its class name or
	 * <code>null</code> if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C removeConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.remove(clazz);
		if (configs == null) {
			return null;
		}
		if (configs.size() != 1) {
			throw new IllegalStateException("Only one configurer expected for type "
					+ clazz + ", but got " + configs);
		}
		return (C) configs.get(0);
	}

	/**
	 * Specifies the {@link ObjectPostProcessor} to use.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use. Cannot be null
	 * @return the {@link SecurityBuilder} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public O objectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		return (O) this;
	}

	/**
	 * Performs post processing of an object. The default is to delegate to the
	 * {@link ObjectPostProcessor}.
	 *
	 * @param object the Object to post process
	 * @return the possibly modified Object to use
	 */
	protected <P> P postProcess(P object) {
		return this.objectPostProcessor.postProcess(object);
	}

	/**
	 * Executes the build using the {@link SecurityConfigurer}'s that have been applied
	 * using the following steps:
	 *
	 * <ul>
	 * <li>Invokes {@link #beforeInit()} for any subclass to hook into</li>
	 * <li>Invokes {@link SecurityConfigurer#init(SecurityBuilder)} for any
	 * {@link SecurityConfigurer} that was applied to this builder.</li>
	 * <li>Invokes {@link #beforeConfigure()} for any subclass to hook into</li>
	 * <li>Invokes {@link #performBuild()} which actually builds the Object</li>
	 * </ul>
	 */
	@Override
	protected final O doBuild() throws Exception {
		synchronized (configurers) {
			buildState = BuildState.INITIALIZING;

			beforeInit();
			init();

			buildState = BuildState.CONFIGURING;

			beforeConfigure();
			configure();

			buildState = BuildState.BUILDING;

			O result = performBuild();

			buildState = BuildState.BUILT;

			return result;
		}
	}

	/**
	 * Invoked prior to invoking each {@link SecurityConfigurer#init(SecurityBuilder)}
	 * method. Subclasses may override this method to hook into the lifecycle without
	 * using a {@link SecurityConfigurer}.
	 */
	protected void beforeInit() throws Exception {
	}

	/**
	 * Invoked prior to invoking each
	 * {@link SecurityConfigurer#configure(SecurityBuilder)} method. Subclasses may
	 * override this method to hook into the lifecycle without using a
	 * {@link SecurityConfigurer}.
	 */
	protected void beforeConfigure() throws Exception {
	}

	/**
	 * Subclasses must implement this method to build the object that is being returned.
	 *
	 * @return the Object to be buit or null if the implementation allows it
	 */
	protected abstract O performBuild() throws Exception;

	@SuppressWarnings("unchecked")
	private void init() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.init((B) this);
		}

		for (SecurityConfigurer<O, B> configurer : configurersAddedInInitializing) {
			configurer.init((B) this);
		}
	}

	@SuppressWarnings("unchecked")
	private void configure() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.configure((B) this);
		}
	}

	private Collection<SecurityConfigurer<O, B>> getConfigurers() {
		List<SecurityConfigurer<O, B>> result = new ArrayList<>();
		for (List<SecurityConfigurer<O, B>> configs : this.configurers.values()) {
			result.addAll(configs);
		}
		return result;
	}

	/**
	 * Determines if the object is unbuilt.
	 * @return true, if unbuilt else false
	 */
	private boolean isUnbuilt() {
		synchronized (configurers) {
			return buildState == BuildState.UNBUILT;
		}
	}

	/**
	 * The build state for the application
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static enum BuildState {
		/**
		 * This is the state before the {@link Builder#build()} is invoked
		 */
		UNBUILT(0),

		/**
		 * The state from when {@link Builder#build()} is first invoked until all the
		 * {@link SecurityConfigurer#init(SecurityBuilder)} methods have been invoked.
		 */
		INITIALIZING(1),

		/**
		 * The state from after all {@link SecurityConfigurer#init(SecurityBuilder)} have
		 * been invoked until after all the
		 * {@link SecurityConfigurer#configure(SecurityBuilder)} methods have been
		 * invoked.
		 */
		CONFIGURING(2),

		/**
		 * From the point after all the
		 * {@link SecurityConfigurer#configure(SecurityBuilder)} have completed to just
		 * after {@link AbstractConfiguredSecurityBuilder#performBuild()}.
		 */
		BUILDING(3),

		/**
		 * After the object has been completely built.
		 */
		BUILT(4);

		private final int order;

		BuildState(int order) {
			this.order = order;
		}

		public boolean isInitializing() {
			return INITIALIZING.order == order;
		}

		/**
		 * Determines if the state is CONFIGURING or later
		 * @return
		 */
		public boolean isConfigured() {
			return order >= CONFIGURING.order;
		}
	}
}

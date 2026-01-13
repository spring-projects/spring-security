package org.springframework.security.web.util.matcher;


import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;


final class DefaultInetAddressVerifierBuilder implements InetAddressFilter.Builder {

	private static final String ALLOWED_DISALLOWED_MESSAGE = "allowed and disallowed are mutually exclusive";

	private static final String INTERNAL_EXTERNAL_ONLY_MESSAGE = "internalOnly and externalOnly are mutually exclusive";

	private final List<InetAddressFilter> filters = new ArrayList<>();

	private boolean reportOnly;

	@Override
	public InetAddressFilter.Builder allowList(List<String> addresses) {
		assertNoneMatch(filter -> filter instanceof DisallowedInetAddressFilter, ALLOWED_DISALLOWED_MESSAGE);
		this.filters.add(new AllowedInetAddressFilter(addresses));
		return this;
	}

	@Override
	public InetAddressFilter.Builder denyList(List<String> addresses) {
		assertNoneMatch(filter -> filter instanceof AllowedInetAddressFilter, ALLOWED_DISALLOWED_MESSAGE);
		this.filters.add(new DisallowedInetAddressFilter(addresses));
		return this;
	}

	@Override
	public InetAddressFilter.Builder blockExternal() {
		return addInternalOrExternalFilter(true);
	}

	@Override
	public InetAddressFilter.Builder blockInternal() {
		return addInternalOrExternalFilter(false);
	}

	private InetAddressFilter.Builder addInternalOrExternalFilter(boolean blockExternal) {

		assertNoneMatch(
				f -> f instanceof InternalExternalInetAddressFilter ief && blockExternal != ief.shouldBlockExternal(),
				INTERNAL_EXTERNAL_ONLY_MESSAGE);

		this.filters.add(new InternalExternalInetAddressFilter(blockExternal));
		return this;
	}

	@Override
	public InetAddressFilter.Builder addCustomFilter(InetAddressFilter filter) {
		this.filters.add(filter);
		return this;
	}

	@Override
	public InetAddressFilter.Builder reportOnly() {
		this.reportOnly = true;
		return this;
	}

	@Override
	public InetAddressFilter build() {
		return new CompositeInetAddressFilter(this.filters, this.reportOnly);
	}

	private void assertNoneMatch(Predicate<InetAddressFilter> predicate, String message) {
		Assert.state(this.filters.stream().noneMatch(predicate), message);
	}


	private record CompositeInetAddressFilter(
			List<InetAddressFilter> filters, boolean reportOnly) implements InetAddressFilter {

		private static final Log logger = LogFactory.getLog(InetAddressFilter.class);

		private CompositeInetAddressFilter(List<InetAddressFilter> filters, boolean reportOnly) {
				this.filters = new ArrayList<>(filters);
				this.reportOnly = reportOnly;
			}

		@Override
		public boolean filter(InetAddress address) {
			boolean result = doFilter(address);
			return (this.reportOnly || result);
		}

		private boolean doFilter(InetAddress address) {
			for (InetAddressFilter filter : this.filters) {
				if (!filter.filter(address)) {
					if (logger.isDebugEnabled()) {
						logger.debug("InetAddress " + address + " blocked by " + filter);
					}
					return false;
				}
			}
			return true;
		}
	}

}

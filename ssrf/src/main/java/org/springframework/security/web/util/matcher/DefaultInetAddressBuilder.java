package org.springframework.security.web.util.matcher;


import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;


final class DefaultInetAddressBuilder implements InetAddressFilter.Builder {

	private final List<InetAddressFilter> filters = new ArrayList<>();

	private boolean reportOnly;

	@Override
	public InetAddressFilter.Builder allowList(List<String> addresses) {
		this.filters.add(new AllowedInetAddressFilter(addresses));
		return this;
	}

	@Override
	public InetAddressFilter.Builder denyList(List<String> addresses) {
		this.filters.add(new DisallowedInetAddressFilter(addresses));
		return this;
	}

	@Override
	public InetAddressFilter.Builder blockExternal() {
		return addInternalExternalFilter(true);
	}

	@Override
	public InetAddressFilter.Builder blockInternal() {
		return addInternalExternalFilter(false);
	}

	private InetAddressFilter.Builder addInternalExternalFilter(boolean blockExternal) {
		Assert.isTrue(this.filters.stream().noneMatch(f ->
				f instanceof InternalExternalInetAddressFilter ief && blockExternal != ief.shouldBlockExternal()),
				"blockExternal and blockInternal are mutually exclusive options");

		this.filters.add(new InternalExternalInetAddressFilter(blockExternal));
		return this;
	}

	@Override
	public InetAddressFilter.Builder customFilter(InetAddressFilter filter) {
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

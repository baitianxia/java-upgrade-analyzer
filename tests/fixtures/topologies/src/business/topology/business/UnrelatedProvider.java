package topology.business;

import topology.spi.TopologyService;

public final class UnrelatedProvider implements TopologyService {
    @Override
    public void execute() {
        " unrelated ".trim();
    }
}

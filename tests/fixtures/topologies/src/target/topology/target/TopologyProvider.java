package topology.target;

import topology.spi.TopologyService;

public final class TopologyProvider implements TopologyService {
    @Override
    public void execute() {
        TargetApi.changed();
    }
}

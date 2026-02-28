"""Layer toggle — runtime enable/disable for each AI protection level.

Allows toggling L1/L2/L3 on the dashboard to test how the system behaves
with different combinations of protection layers.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)

# In-memory state (all enabled by default)
layer_state: Dict[str, bool] = {
    "L1": True,
    "L2": True,
    "L3": True,
}


def set_layer(layer: str, enabled: bool) -> bool:
    """Enable or disable a layer. Returns True if successful."""
    if layer not in layer_state:
        return False
    layer_state[layer] = enabled
    logger.info("Layer %s %s", layer, "ENABLED" if enabled else "DISABLED")
    return True


def get_layers() -> Dict[str, bool]:
    """Return current state of all layers."""
    return dict(layer_state)


def is_enabled(layer: str) -> bool:
    """Check if a layer is enabled."""
    return layer_state.get(layer, True)


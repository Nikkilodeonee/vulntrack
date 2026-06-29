package com.vulntrack.enums;

public enum AssetCriticality {
    LOW(1.0),
    MEDIUM(1.2),
    HIGH(1.5),
    CRITICAL(2.0);

    private final double multiplier;

    AssetCriticality(double multiplier) {
        this.multiplier = multiplier;
    }

    public double getMultiplier() {
        return multiplier;
    }
}

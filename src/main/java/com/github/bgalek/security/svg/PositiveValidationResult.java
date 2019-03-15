package com.github.bgalek.security.svg;

import java.util.Set;

class PositiveValidationResult implements ValidationResult {
    private final Set<String> offendingElements;

    PositiveValidationResult(Set<String> offendingElements) {
        this.offendingElements = offendingElements;
    }

    @Override
    public boolean hasViolations() {
        return true;
    }

    @Override
    public Set<String> getOffendingElements() {
        return offendingElements;
    }

}

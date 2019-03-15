package com.github.bgalek.security.svg;

import java.util.Collections;
import java.util.Set;

class NegativeValidationResult implements ValidationResult {

    @Override
    public boolean hasViolations() {
        return false;
    }

    @Override
    public Set<String> getOffendingElements() {
        return Collections.emptySet();
    }
}

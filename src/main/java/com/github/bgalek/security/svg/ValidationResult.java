package com.github.bgalek.security.svg;

import java.util.Set;

/**
 * Safe-svg Validation Results interface
 */
public interface ValidationResult {
    /**
     * @return are there any violations found
     */
    boolean hasViolations();

    /**
     * @return set of invalid elements or attributes found in SVG content
     */
    Set<String> getOffendingElements();
}

package com.github.bgalek.security.svg;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.owasp.html.CssSchema;
import org.owasp.html.HtmlChangeListener;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * SVG Safe is a very simple and lightweight library that helps
 * to validate SVG files in security manners.
 * It will help you in detecting malicious content inside uploaded SVGs.
 *
 * @author Bartosz Gałek
 * @see <a href="https://github.com/bgalek/safe-svg">safe-svg</a>
 */
public class SvgSecurityValidator implements XssDetector {

    private static final Pattern JAVASCRIPT_PROTOCOL_IN_CSS_URL = Pattern.compile("url\\(.?javascript");

    private final String[] svgElements;
    private final String[] svgAttributes;

    private SvgSecurityValidator(String[] elements, String[] attributes) {
        this.svgElements = elements;
        this.svgAttributes = attributes;
    }

    public SvgSecurityValidator() {
        this(SVG_ELEMENTS, SVG_ATTRIBUTES);
    }

    public SvgSecurityValidator(List<String> additionalElements, List<String> additionalAttributes) {
        this.svgElements = Stream.concat(Arrays.stream(SVG_ELEMENTS), additionalElements.stream()).distinct().toArray(String[]::new);
        this.svgAttributes = Stream.concat(Arrays.stream(SVG_ATTRIBUTES), additionalAttributes.stream()).distinct().toArray(String[]::new);
    }

    /**
     * This is the main method that handles svg file validation
     *
     * @param input svg file content to validate
     * @return {@link ValidationResult}
     * @since 1.0
     */
    @Override
    public ValidationResult validate(String input) {
        Set<String> offendingElements = getOffendingElements(input);
        if (offendingElements.isEmpty()) return new NegativeValidationResult();
        return new PositiveValidationResult(offendingElements);
    }

    @Override
    public ValidationResult validate(byte[] input) {
        return validate(new String(input, StandardCharsets.UTF_8));
    }

    private Set<String> getOffendingElements(String xml) {
        if (JAVASCRIPT_PROTOCOL_IN_CSS_URL.matcher(xml).find()) return Collections.singleton("style");
        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements(this.svgElements)
                .allowStyling(CssSchema.union(CssSchema.DEFAULT, CssSchema.withProperties(SVG_SPECIFIC_STYLES)))
                .allowAttributes(this.svgAttributes).globally()
                .allowUrlProtocols("https")
                .toFactory();
        Set<String> violations = new HashSet<>();
        policy.sanitize(xml, violationsCollector(), violations);
        return violations;
    }

    private static final ImmutableMap<String, CssSchema.Property> SVG_SPECIFIC_STYLES = ImmutableMap.of(
            "enable-background", new CssSchema.Property(1, ImmutableSet.of(), ImmutableMap.of())
    );

    /**
     * @see <a href="https://developer.mozilla.org/en-US/docs/Web/SVG/Element">
     * https://developer.mozilla.org/en-US/docs/Web/SVG/Element
     * </a>
     */
    private static final String[] SVG_ELEMENTS = {
            "svg",
            "altGlyph",
            "altGlyphDef",
            "altGlyphItem",
            "animateColor",
            "animateMotion",
            "animateTransform",
            "circle",
            "clipPath",
            "defs",
            "desc",
            "discard",
            "ellipse",
            "filter",
            "font",
            "g",
            "glyph",
            "glyphRef",
            "hkern",
            "image",
            "line",
            "linearGradient",
            "marker",
            "mask",
            "metadata",
            "mpath",
            "path",
            "pattern",
            "polygon",
            "polyline",
            "radialGradient",
            "rect",
            "stop",
            "style",
            "svg",
            "switch",
            "symbol",
            "text",
            "textPath",
            "title",
            "tref",
            "tspan",
            "use",
            "view",
            "vkern",
            "feBlend",
            "feColorMatrix",
            "feComponentTransfer",
            "feComposite",
            "feConvolveMatrix",
            "feDiffuseLighting",
            "feDisplacementMap",
            "feDistantLight",
            "feFlood",
            "feFuncA",
            "feFuncB",
            "feFuncG",
            "feFuncR",
            "feGaussianBlur",
            "feMerge",
            "feMergeNode",
            "feMorphology",
            "feOffset",
            "fePointLight",
            "feSpecularLighting",
            "feSpotLight",
            "feTile",
            "feTurbulence"
    };

    /**
     * @see <a href="https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute">
     * https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute
     * </a>
     */

    private static final String[] SVG_ATTRIBUTES = {
            "accent-height",
            "accumulate",
            "additive",
            "alignment-baseline",
            "ascent",
            "attributeName",
            "attributeType",
            "azimuth",
            "baseProfile",
            "baseFrequency",
            "baseline-shift",
            "begin",
            "bias",
            "by",
            "calcMode",
            "class",
            "clip",
            "clipPathUnits",
            "clip-path",
            "clip-rule",
            "color",
            "color-interpolation",
            "color-interpolation-filters",
            "color-profile",
            "color-rendering",
            "cx",
            "cy",
            "d",
            "dx",
            "dy",
            "diffuseConstant",
            "direction",
            "display",
            "divisor",
            "dur",
            "edgeMode",
            "elevation",
            "end",
            "exponent",
            "fill",
            "fill-opacity",
            "fill-rule",
            "filter",
            "flood-color",
            "flood-opacity",
            "font-family",
            "font-size",
            "font-size-adjust",
            "font-stretch",
            "font-style",
            "font-variant",
            "font-weight",
            "from",
            "fr",
            "fx",
            "fy",
            "g1",
            "g2",
            "glyph-name",
            "glyphRef",
            "gradientTransform",
            "gradientUnits",
            "height",
            "href",
            "id",
            "image-rendering",
            "in",
            "in2",
            "intercept",
            "k",
            "k1",
            "k2",
            "k3",
            "k4",
            "kernelMatrix",
            "kernelUnitLength",
            "kerning",
            "keyPoints",
            "keySplines",
            "keyTimes",
            "lang",
            "lengthAdjust",
            "letter-spacing",
            "lighting-color",
            "limitingConeAngle",
            "local",
            "marker-end",
            "marker-mid",
            "marker-start",
            "markerHeight",
            "markerUnits",
            "markerWidth",
            "mask",
            "maskContentUnits",
            "maskUnits",
            "max",
            "media",
            "method",
            "min",
            "mode",
            "name",
            "numOctaves",
            "offset",
            "operator",
            "opacity",
            "order",
            "orient",
            "orientation",
            "origin",
            "overflow",
            "paint-order",
            "path",
            "pathLength",
            "patternContentUnits",
            "patternTransform",
            "patternUnits",
            "pointer-events",
            "points",
            "pointsAtX",
            "pointsAtY",
            "pointsAtZ",
            "preserveAlpha",
            "preserveAspectRatio",
            "primitiveUnits",
            "r",
            "radius",
            "refX",
            "refY",
            "repeatCount",
            "repeatDur",
            "restart",
            "result",
            "rotate",
            "rx",
            "ry",
            "scale",
            "seed",
            "shape-rendering",
            "specularConstant",
            "specularExponent",
            "spreadMethod",
            "startOffset",
            "stdDeviation",
            "stitchTiles",
            "strikethrough-position",
            "strikethrough-thickness",
            "stop-color",
            "stop-opacity",
            "stroke-dasharray",
            "stroke-dashoffset",
            "stroke-linecap",
            "stroke-linejoin",
            "stroke-miterlimit",
            "stroke-opacity",
            "stroke",
            "stroke-width",
            "style",
            "surfaceScale",
            "systemLanguage",
            "tabindex",
            "tableValues",
            "targetX",
            "targetY",
            "text-anchor",
            "text-decoration",
            "text-rendering",
            "textLength",
            "to",
            "transform",
            "transform-origin",
            "type",
            "u1",
            "u2",
            "underline-position",
            "underline-thickness",
            "unicode",
            "unicode-bidi",
            "version",
            "values",
            "vector-effect",
            "viewBox",
            "viewTarget",
            "visibility",
            "vert-adv-y",
            "vert-origin-x",
            "vert-origin-y",
            "width",
            "word-spacing",
            "wrap",
            "writing-mode",
            "xChannelSelector",
            "x",
            "x1",
            "x2",
            "xlink:href",
            "xmlns",
            "xml:lang",
            "xml:space",
            "xmlns:xlink",
            "y",
            "y1",
            "y2",
            "yChannelSelector",
            "z",
            "zoomAndPan"
    };

    private static HtmlChangeListener<Set<String>> violationsCollector() {
        return new ListHtmlChangeListener();
    }

    private static class ListHtmlChangeListener implements HtmlChangeListener<Set<String>> {
        @Override
        public void discardedTag(Set<String> context, String elementName) {
            Objects.requireNonNull(context).add(elementName);
        }

        @Override
        public void discardedAttributes(Set<String> context, String tagName, String... attributeNames) {
            Objects.requireNonNull(context).addAll(Arrays.asList(attributeNames));
        }
    }
}

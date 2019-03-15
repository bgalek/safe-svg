package com.github.bgalek.security.svg;

import org.owasp.html.HtmlChangeListener;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * SVG Safe is a very simple and lightweight library that helps
 * to validate SVG files in security manners.
 * It will help you in detecting malicious content inside uploaded SVGs.
 *
 * @author Bartosz Gałek
 * @see <a href="https://github.com/bgalek/safe-svg">safe-svg</a>
 */
public class SvgSecurityValidator implements XssDetector {

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

    private static Set<String> getOffendingElements(String xml) {
        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements(SVG_ELEMENTS)
                .allowStyling()
                .allowAttributes(SVG_ATTRIBUTES).globally()
                .allowUrlProtocols("https")
                .toFactory();
        Set<String> violations = new HashSet<>();
        policy.sanitize(xml, violationsCollector(), violations);
        return violations;
    }

    /**
     * @see <a href="https://developer.mozilla.org/en-US/docs/Web/SVG/Element">
     * https://developer.mozilla.org/en-US/docs/Web/SVG/Element
     * </a>
     */
    private static final String[] SVG_ELEMENTS = {
            "svg",
            "altglyph",
            "altglyphdef",
            "altglyphitem",
            "animatecolor",
            "animatemotion",
            "animatetransform",
            "circle",
            "clippath",
            "defs",
            "desc",
            "ellipse",
            "filter",
            "font",
            "g",
            "glyph",
            "glyphref",
            "hkern",
            "image",
            "line",
            "lineargradient",
            "marker",
            "mask",
            "metadata",
            "mpath",
            "path",
            "pattern",
            "polygon",
            "polyline",
            "radialgradient",
            "rect",
            "stop",
            "switch",
            "symbol",
            "text",
            "textpath",
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
            "additivive",
            "alignment-baseline",
            "ascent",
            "attributename",
            "attributetype",
            "azimuth",
            "baseprofile",
            "basefrequency",
            "baseline-shift",
            "begin",
            "bias",
            "by",
            "class",
            "clip",
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
            "diffuseconstant",
            "direction",
            "display",
            "divisor",
            "dur",
            "edgemode",
            "elevation",
            "end",
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
            "fx",
            "fy",
            "g1",
            "g2",
            "glyph-name",
            "glyphref",
            "gradientunits",
            "gradienttransform",
            "height",
            "href",
            "id",
            "image-rendering",
            "in",
            "in2",
            "k",
            "k1",
            "k2",
            "k3",
            "k4",
            "kerning",
            "keypoints",
            "keysplines",
            "keytimes",
            "lang",
            "lengthadjust",
            "letter-spacing",
            "kernelmatrix",
            "kernelunitlength",
            "lighting-color",
            "local",
            "marker-end",
            "marker-mid",
            "marker-start",
            "markerheight",
            "markerunits",
            "markerwidth",
            "maskcontentunits",
            "maskunits",
            "max",
            "mask",
            "media",
            "method",
            "mode",
            "min",
            "name",
            "numoctaves",
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
            "pathlength",
            "patterncontentunits",
            "patterntransform",
            "patternunits",
            "points",
            "preservealpha",
            "preserveaspectratio",
            "r",
            "rx",
            "ry",
            "radius",
            "refx",
            "refy",
            "repeatcount",
            "repeatdur",
            "restart",
            "result",
            "rotate",
            "scale",
            "seed",
            "shape-rendering",
            "specularconstant",
            "specularexponent",
            "spreadmethod",
            "stddeviation",
            "stitchtiles",
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
            "surfacescale",
            "tabindex",
            "targetx",
            "targety",
            "transform",
            "text-anchor",
            "text-decoration",
            "text-rendering",
            "textlength",
            "type",
            "u1",
            "u2",
            "unicode",
            "version",
            "values",
            "viewbox",
            "visibility",
            "vert-adv-y",
            "vert-origin-x",
            "vert-origin-y",
            "width",
            "word-spacing",
            "wrap",
            "writing-mode",
            "xchannelselector",
            "ychannelselector",
            "x",
            "x1",
            "x2",
            "xmlns",
            "y",
            "y1",
            "y2",
            "z",
            "zoomandpan"
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

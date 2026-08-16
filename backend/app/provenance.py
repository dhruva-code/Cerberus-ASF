"""
Classifies a decompiled Java source path as belonging to the app's own
code, a known third-party SDK, or neither (unknown).

This exists to separate signal from noise: a jadx decompile of a real APK
walks every bundled library too (Google Play Services, AndroidX support,
etc.), and structural rule hits inside vendored code are real but rarely
actionable for the app's own developers. Provenance tagging lets callers
default to showing app-code issues while keeping everything else
available, not discarded.
"""

KNOWN_THIRD_PARTY_PREFIXES = [
    "com/google/android/gms", "com/google/firebase", "com/google/android/material",
    "android/support/", "androidx/", "kotlin/", "kotlinx/",
    "com/facebook/", "com/squareup/", "okhttp3/", "retrofit2/",
    "org/apache/", "org/json/", "javax/", "org/jetbrains/",
    "com/google/gson/", "com/bumptech/glide/",
]


def classify(package_name: str, relative_java_path: str) -> str:
    """Returns "app", "third_party", or "unknown".

    If package_name couldn't be determined (aapt extraction failed and
    fell back to the placeholder), we can't confirm anything is app code,
    so unmatched paths fall to "unknown" rather than "third_party" —
    unknown is shown by default, third_party is hidden by default, and
    silently hiding real app findings when provenance can't be
    established would be worse than showing some vendor noise."""
    normalized_path = relative_java_path.replace("\\", "/")
    known_package = bool(package_name) and package_name != "generic.android.target"

    if known_package:
        app_prefix = package_name.replace(".", "/") + "/"
        if normalized_path.startswith(app_prefix):
            return "app"

    for prefix in KNOWN_THIRD_PARTY_PREFIXES:
        if normalized_path.startswith(prefix):
            return "third_party"

    return "third_party" if known_package else "unknown"

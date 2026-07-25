/*
 * VulnHunter Android static-analysis rules.
 *
 * These rules deliberately identify narrow evidence conditions. A match is a
 * candidate observation, not proof of exploitability or impact.
 */

rule android_embedded_private_key : credential high_confidence
{
    meta:
        title = "Private key material is embedded in the application"
        weakness_id = "cwe-321"
        severity = "high"
        confidence = "verified_content"
    strings:
        $pkcs8 = "-----BEGIN PRIVATE KEY-----" ascii wide
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii wide
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii wide
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii wide
    condition:
        any of them
}

rule android_cloud_access_key_identifier : credential review_required
{
    meta:
        title = "Cloud access-key identifier is embedded in the application"
        weakness_id = "cwe-798"
        severity = "medium"
        confidence = "evidence_required"
    strings:
        $aws = /AKIA[0-9A-Z]{16}/ ascii
    condition:
        $aws
}

rule android_webview_javascript_bridge_surface : webview review_required
{
    meta:
        title = "WebView JavaScript bridge attack surface is present"
        weakness_id = "cwe-749"
        severity = "medium"
        confidence = "evidence_required"
    strings:
        $bridge = "addJavascriptInterface" ascii wide
        $javascript = "setJavaScriptEnabled" ascii wide
    condition:
        all of them
}

rule android_remote_dynamic_code_loading_surface : dynamic_loading review_required
{
    meta:
        title = "Remote dynamic-code loading surface is present"
        weakness_id = "cwe-494"
        severity = "medium"
        confidence = "evidence_required"
    strings:
        $loader1 = "DexClassLoader" ascii wide
        $loader2 = "PathClassLoader" ascii wide
        $remote1 = "http://" ascii wide nocase
        $remote2 = "https://" ascii wide nocase
    condition:
        any of ($loader*) and any of ($remote*)
}

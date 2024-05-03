rule Detect_Redtail_Malware {
    meta:
        description = "YARA rule to detect Redtail malware based on specific indicators"
        author = "Exylum Technical"
        reference = "https://exylum.tech/blog/23-12-html-scanning.html"

    strings:
        $url_string = "dw.ohuyal.xyz"
        $ip1_string = "8.212.169.72"
        $ip2_string = "45.95.147.236"
        $redtail_string = "redtail"
		$hash1 = "9e822d3f3957e60156140d281ae5519b0f6d4277045e79cb266a37b8c70e44e5"
		$hash2 = "eb609a31f3798e3c754f1f0198c55b5445fdb692969e19521a55f8792758dc2d"
		$hash3 = "453be80cc7125682acbaa4b2d90abf9e62aa74187e45342257830111a5d2e054"
		$hash4 = "f3f7eb972a998047edb4c6e4287308236fcd8a9ef81dc13e6469590275af3cac"

    condition:
        any of them or
        1 of ($hash*)
}

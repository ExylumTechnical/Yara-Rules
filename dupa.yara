rule dupa_cryptominer {
    meta:
        description = "YARA rule for dupa crypto miner. Note that the filename javat may produce false positives."
        author = "Exylum"
        reference = "IOC rule based on blog post at https://exylum.tech/blog/honeypot-23-11.html"
    
    strings:
        $hash1 = "ac80f84043b824c7e0b68dee20412bc51177d3c8db61f5aeea90655969e66507"
        $hash2 = "d6834b311280f9074b74d20ba2025e33e27460e197c132729e90c030dd893d18"
        $hash3 = "e7cc20711ef8c20345974908a259002a893921d96bee5aac16dac54df6507f4a"
        $hash4 = "0386f712ba8b57c4b72fd48ca524b6c2b4c191362037b2fa09c11fcd8c9121a7"
        $hash5 = "bbd39a020950b30c23c7c42782856e634c6bec6ef489cc2835ff822fb23a7368"
        $ip1 = "185.225.75.242"
        $ip2 = "75.119.147.155"
		$filename1 = "dupa.sh"
		$filename2 = "xmrig.arm7"
		$filename3 = "xmrig.arm8"
		$filename4 = "xmrig.i686"
		$filename5 = "xmrig.x86_64"
		$filename6 = "javat"
		
    condition:
        any of ($hash*) or any of ($ip*)
}

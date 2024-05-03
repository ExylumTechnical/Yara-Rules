rule dota3_malware
{
    meta:
        description = "YARA rule to detect dota3 crypto malware based on specific indicators"
        author = "Exylum Technical"
        reference = "https://exylum.tech/blog/23-12-html-scanning.html"
    strings:
          $file_dota1 = "/tmp/.X19-unix/.rsync/c/tsm"
          $file_dota2 = "/tmp/up.txt"
          $directory_dota1 = "/tmp/.X19-unix/.rsync/c"
          $file_dota3 = "/tmp/dota3.tar.gz"
          $file_dota4 = "/var/tmp/.var03522123"
    condition:
          any of them
}

rule dota3_bash_irc
{
      meta:
        description = "YARA rule to detect dota3 communication over irc"
        author = "Exylum Technical"
        reference = "https://exylum.tech/blog/23-12-html-scanning.html"
      string:
        url = "pool.supportxmr.com"
        base64 = "ICAgICAgIFtbICIkbGluZSIgPT0gJCdccicgXV0gJiYgYnJ1YWs"
       condition:
        any of them
}

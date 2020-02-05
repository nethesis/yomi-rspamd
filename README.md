# INTRO

YOMI RSPAMD it's a lua plugin that, in combination with <a href="https://github.com/nethesis/yomi-proxy">yomi-proxy</a>, permit to analize every mail attachment sent from rspamd to <a href="https://yoroi.company">yoroi sandbox (YOMI)</a>.
Before install this package, you has to install <a href="https://github.com/nethesis/yomi-proxy">yomi-proxy</a>.

# PREREQUISITE

- rspamd

# INSTALLATION

Clone this repository on your local server.

>git clone https://github.com/nethesis/yomi-rspamd

copy yomi.lua file on directory :

> /usr/share/rspamd/lualib/lua_scanners/

Bash command executed inside yomi-rspamd directory:

> cp yomi.lua /usr/share/rspamd/lualib/lua_scanners/

# CONFIGURE

YOMI RSPAMD has basic configuration setup.

Fist, edit the antivirus.conf located on :

>/etc/rspamd/local.d/antivirus.conf

with that :

````
yoroi {
  action = "reject";
  message = '$SCANNER: virus found: "$VIRUS"';
  scan_mime_parts = true;
  max_size = 20000000;
  symbol = "CLAM_VIRUS";
  type = "yomi";
  log_clean = true;
  whitelist = "/etc/rspamd/antivirus.wl";
  url = "http://192.168.x.y:5000"	 
}

````

Second, edit the file yomi.lua located on :

>/usr/share/rspamd/lualib/lua_scanners/yomi.lua

and change only the url variable with **your** yomi-proxy server url.

````  
local default_conf = {
    name = N,
    url = "http://192.168.x.y:5000",
    timeout = 5.0,
    log_clean = true,
    retransmits = 1,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false, 
````

>url = "http://192.168.x.y:5000", 

Save and exit.

Restart rspamd with :
>systemctl restart rspamd

#Test 

Send an email and check if the attachment its a malware.

![alt text](img/test.png)

Tested with EICAR-TEST





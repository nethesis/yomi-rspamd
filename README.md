# INTRO

YOMI RSPAMD it's a lua plugin that, in combination with <a href="https://github.com/nethesis/yomi-proxy">yomi-proxy</a>, permit to analize every mail attachment sent from rspamd to <a href="https://yoroi.company">yoroi sandbox (YOMI)</a>.
Before install this package, you has to install <a href="https://github.com/nethesis/yomi-proxy">yomi-proxy</a>.

# PREREQUISITE

- rspamd

# INSTALLATION

Clone this repository on your local server:
```
git clone https://github.com/nethesis/yomi-rspamd
```

Copy yomi.lua file on directory :

```
cp yomi.lua /usr/share/rspamd/lualib/lua_scanners/
```

Add the below line inside  `/usr/share/rspamd/lualib/lua_scanners/init.lua` under the `---Antiviruses` section:
```
require_scanner('yomi')
```

# CONFIGURE


Enable yomi scanner  inside rspamd `/etc/rspamd/local.d/antivirus.conf`:

```
enabled = true

yomi {
  type = "yomi";
  url = "https://sb.nethesis.it";
  virus_score = 0.8;
  suspicious_score = 0.4;
  system_id = "my_system_id";
  secret = "my_system_secret";
}
```

## Symbols

The rspamd plugin can insert the following symbols inside the mail header:

- `YOMI_FAIL`: if the proxy or upstream service has failed
- `YOMI_VIRUS`: if the given  is a virus (score is greater than 0.7)
- `YOMI_CLEAN`: if the given file is not a virus
- `YOMI_WAIT`: if the file is being processed inside the Sandbox, also add the `CLAM_VIRUS_FAIL` symbol to handle the soft reject


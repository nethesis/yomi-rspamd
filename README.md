# INTRO

This is lua plugin for Rspamd that, in combination with <a href="https://github.com/nethesis/yomi-proxy">yomi-proxy</a>, analizes every mail attachment through the <a href="https://yoroi.company">Yoroi Yomi sandbox (YOMI)</a>.
Before installing this package, you have to install the <a href="https://github.com/nethesis/yomi-proxy">yomi-proxy</a>.

# PREREQUISITE

- Rspamd

# INSTALLATION

Clone this repository to your local server:
```
git clone https://github.com/nethesis/yomi-rspamd
```

Copy yomi.lua file to Rspamd plugins directory :

```
cp yomi.lua /usr/share/rspamd/lualib/lua_scanners/
```

Add the line below inside  `/usr/share/rspamd/lualib/lua_scanners/init.lua` under the `---Antiviruses` section:
```
require_scanner('yomi')
```

# CONFIGURE


Enable yomi scanner inside rspamd `/etc/rspamd/local.d/antivirus.conf`:

```
enabled = true

yomi {
  type = "yomi";
  url = "https://<yomi-proxy>.nethesis.it";
  virus_score = 0.8;
  suspicious_score = 0.4;
  system_id = "my_system_id";
  secret = "my_system_secret";
}
```

## Symbols

The rspamd plugin can insert the following symbols inside the mail header:

- `YOMI_FAIL`: if the proxy or upstream service has failed
- `YOMI_VIRUS`: if the given file is a virus (score is greater than 0.7 by default)
- `YOMI_SUSPICIOUS`: if the given file is suspicious (score is between 0.4 and 0.7 by default)
- `YOMI_CLEAN`: if the given file is not a virus
- `YOMI_UNKNOWN`: the Sandbox wasn't able to compute a score for the file
- `YOMI_WAIT`: if the file is being processed inside the Sandbox, also add the CLAM_VIRUS_FAIL symbol to handle the soft reject
- `YOMI_UNAUTHORIZED`: if the proxy cannot grant authentication or authorization
- `YOMI_SKIPPED`: if YOMI check was skipped because the sender is authenticated or the MIME type of the file is considered safe

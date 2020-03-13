-- Yomi sandbox integration

local lua_util = require "lua_util"
local http = require "rspamd_http"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

local N = 'yomi'

function Set (list)
  local set = {}
  for _, l in ipairs(list) do
    set[l] = true
  end
  return set
end

local function yomi_config(opts)

  local default_conf = {
    name = N,
    url = "http://yomi.nethserver.net:8080/api",
    timeout = 5.0,
    log_clean = true,
    retransmits = 3,
    retransmit_delay = 3,
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    virus_score = 0.7,
    suspicious_score = 0.4,
    skip_mime_types = {} -- file types to skip, e.g. { "pdf", "epub" }
  }

  default_conf = lua_util.override_defaults(default_conf, opts)

  if not default_conf.prefix then
    default_conf.prefix = 'rs_' .. default_conf.name .. '_'
  end

  if not default_conf.log_prefix then
    if default_conf.name:lower() == default_conf.type:lower() then
      default_conf.log_prefix = default_conf.name
      default_conf.log_prefix = default_conf.name
    else
      default_conf.log_prefix = default_conf.name .. ' (' .. default_conf.type .. ')'
    end
  end

  default_conf.skip_mime_types = Set(default_conf.skip_mime_types)
  lua_util.add_debug_alias('external_services', default_conf.name)
  return default_conf
end

local function sleep(n)
  os.execute("sleep " .. tonumber(n))
end

local function should_retransmit()
  if rule.retransmits > 0 then
    rule.retransmits = rule.retransmits -1
    sleep(rule.retransmit_delay)
    return true
  else
    task:insert_result('YOMI_FAIL', 1, 'Maximum retransmits exceed')
  end
  
  return false
end

local function handle_yomi_result(result, task, rule)
  local score = result['score']
  local malware_description = result['description']
  rspamd_logger.infox(task, '%s: Yomi response score: %s, description: %s', rule.log_prefix, score, malware_description)

  -- A file is a virus if the score is greater than virus_score
  if score > rule.virus_score then
    task:insert_result('YOMI_VIRUS', 1, 'Virus found by Yomi: ' .. malware_description)
  elseif score > rule.suspicious_score then
    task:insert_result('YOMI_SUSPICIOUS', 1, 'Suspicious file found by Yomi: ' .. malware_description)
  elseif score < 0 then
    task:insert_result('YOMI_UNKNOWN', 1, "Yomi wasn't able to compute a score: " .. malware_description)
  else
    task:insert_result('YOMI_CLEAN', 1, 'File is clean')
  end
end

local function yomi_upload(task, content, hash, auth, rule)
  rspamd_logger.infox(task, '%s: uploading to sandbox', rule.log_prefix)

  local request_data = {
    task = task,
    url = string.format('%s/submit', rule.url),
    timeout = rule.timeout,
    method = 'POST',
    mime_type='application/json',
    headers = {
      ['Authorization'] = auth
    },
    body = string.format('{"file": "%s", "hash": "%s"}', rspamd_util.encode_base64(content), hash)
  }

  local function upload_http_callback(http_err, code, body, headers)
    if http_err then
      rspamd_logger.errx(task, 'HTTP error: %s, body: %s, headers: %s', http_err, body, headers)
      
      if should_retransmit() then
        upload_http_callback(http_err, code, body, headers)
      end
    else
      rspamd_logger.infox(task, '%s: upload returned %s', rule.log_prefix, code)

      if code == 202 then
        task:insert_result('YOMI_WAIT', 1, 'File uploaded')
        task:insert_result('CLAM_VIRUS_FAIL', 1, 'File uploaded')
      elseif code == 401 or code == 403 then
        task:insert_result('YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
      elseif code == 200 then
        local parser = ucl.parser()
        local res,json_err = parser:parse_string(body)

        if res then
          local obj = parser:get_object()
          handle_yomi_result(obj, task, rule)
        else
          -- not res
          rspamd_logger.errx(task, 'Yomi invalid response')
          
          if should_retransmit() then
            upload_http_callback(http_err, code, body, headers)
          end
        end
      else
        rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
        
        if should_retransmit() then
          upload_http_callback(http_err, code, body, headers)
        end
      end
    end
  end

  request_data.callback = upload_http_callback
  http.request(request_data)
end

local function should_skip_mime(task, content, rule)
  local mime_parts = task:get_parts() or {}

  for _, mime_part in ipairs(mime_parts) do
    local string_content = tostring(content)
    local string_part_content = tostring(mime_part:get_content())

    if string_content == string_part_content then
      local detected_type = mime_part:get_detected_ext()

      if rule.skip_mime_types[detected_type] then
        rspamd_logger.infox(task, 'File not submitted because of its mime type: %s', detected_type)
        return true
      end
    end
  end
  return false
end

local function yomi_check(task, content, digest, rule)
  rspamd_logger.infox(task, '%s: executing Yomi virus check', rule.log_prefix)

  if should_skip_mime(task, content, rule) then
    task:insert_result('YOMI_MIME_SKIPPED', 1, 'File not submitted because of its mime type')
    return
  end

  local system_id = rule.system_id
  local secret = rule.secret
  local auth = string.format("Basic %s", rspamd_util.encode_base64(system_id .. ":" .. secret))

  local hash = rspamd_cryptobox_hash.create_specific('sha256')
  hash:update(content)
  hash = hash:hex()

  local url = string.format('%s/hash/%s', rule.url, hash)
  rspamd_logger.infox(task, '%s: sending request %s', rule.log_prefix, url)

  local request_data = {
    task = task,
    url = url,
    timeout = rule.timeout,
    headers = {
      ['Authorization'] = auth
    },
  }

  local function hash_http_callback(http_err, code, body, headers)
    if http_err then
      rspamd_logger.errx(task, 'HTTP error: %s, body: %s, headers: %s', http_err, body, headers)
      
      if should_retransmit() then
        hash_http_callback(http_err, code, body, headers)
      end
    else
      rspamd_logger.infox(task, '%s: hash returned %s', rule.log_prefix, code)

      if code == 404 then
        if rule['log_clean'] then
          rspamd_logger.infox(task, '%s: hash %s not found', rule.log_prefix, hash)
        end
        yomi_upload(task, content, hash, auth, rule)
      elseif code == 401 or code == 403 then
        task:insert_result('YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
      elseif code == 202 then
        task:insert_result('YOMI_WAIT', 1, 'Sandbox in progress')
        task:insert_result('CLAM_VIRUS_FAIL', 1, 'Sandbox in progress')
      elseif code == 200 then
        local parser = ucl.parser()
        local res,json_err = parser:parse_string(body)

        if res then
          local obj = parser:get_object()
          handle_yomi_result(obj, task, rule)
        else
          -- not res
          rspamd_logger.errx(task, 'Yomi invalid response')
          
          if should_retransmit() then
            hash_http_callback(http_err, code, body, headers)
          end
        end
      else
        rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
        
        if should_retransmit() then
          hash_http_callback(http_err, code, body, headers)
        end
      end
    end
  end

  request_data.callback = hash_http_callback
  http.request(request_data)
end

return {
  type = 'antivirus',
  description = 'Yomi sandbox integration',
  configure = yomi_config,
  check = yomi_check,
  name = N
}

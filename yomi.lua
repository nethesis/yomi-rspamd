-- Yomi sandbox integration

local lua_util = require "lua_util"
local http = require "rspamd_http"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
-- local common = require "lua_scanners/common"

local N = 'yomi'

local function yomi_config(opts)

  local default_conf = {
    name = N,
    url = "http://127.0.0.1:5000",
    timeout = 5.0,
    log_clean = true,
    retransmits = 1,
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false
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


  lua_util.add_debug_alias('external_services', default_conf.name)
  return default_conf
end

local function yomi_upload(task, content, rule)
     rspamd_logger.infox(task, '%s: uploading to sandbox', rule.log_prefix)
     local request_data = {
      task = task,
      url = string.format('%s/submit', rule.url),
      timeout = rule.timeout,
      method = 'POST',
      mime_type='application/json',
      body = string.format('{"data": "%s"}', rspamd_util.encode_base64(content))
    }


    local function yupd_http_callback(http_err, code, body, headers)
        rspamd_logger.infox(task, '%s: upload returned %s', rule.log_prefix, code)
        task:insert_result('YOMI_WAIT', 0, 'Uploaded')
        return
    end

    request_data.callback = yupd_http_callback
    http.request(request_data)
end
 
local function yomi_check(task, content, digest, rule)
  rspamd_logger.infox(task, '%s: executing Yomi virus check', rule.log_prefix)

    local hash = rspamd_cryptobox_hash.create_specific('sha256')
    hash:update(content)
    hash = hash:hex()

    local url = string.format('%s/hash/%s', rule.url, hash)
    rspamd_logger.infox(task, '%s: sending request %s', rule.log_prefix, url)
    local request_data = {
      task = task,
      url = url,
      timeout = rule.timeout,
    }
      

    local function yhash_http_callback(http_err, code, body, headers)
      if http_err then
        rspamd_logger.errx(task, 'HTTP error: %s, body: %s, headers: %s', http_err, body, headers)
      else
        -- Parse the response
        if code ~= 200 then
          if code == 404 then
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s: hash %s not found',
                  rule.log_prefix, hash)
            end
            yomi_upload(task, content, rule)
            task:insert_result('CLAM_VIRUS_FAIL', 1, 'Unknown file. uploading sample')

          elseif code == 429 then
            -- Request rate limit exceeded
            rspamd_logger.infox(task, 'yomi request rate limit exceeded')
            task:insert_result('CLAM_VIRUS_FAIL', 1, 'Rate limit exceeded')
            task:insert_result('YOMI_WAIT', 1, 'Rate limit exceeded')
            return
          else
            rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
            task:insert_result('YOMI_FAIL', 1, 'Bad HTTP code: ' .. code)
            return
          end
        else
          local ucl = require "ucl"
          local parser = ucl.parser()
          local res,json_err = parser:parse_string(body)


          if res then
            local obj = parser:get_object()
            rspamd_logger.infox(task, '%s: Yomi response score: %s', rule.log_prefix, obj['score'])
            if not obj['score'] or type(obj['score']) ~= 'number' or  obj['score'] == '' then
                task:insert_result('CLAM_VIRUS_FAIL', 1, 'Sandbox in progress')
                task:insert_result('YOMI_WAIT', 1, 'Sandbox in progress')
            else
                -- A file is a virus if the score is 1
                if obj['score'] == 1 then
                    local sopt = string.format("%s:%s", obj['malware'],obj['score'])
                     -- common.yield_result(task, rule, sopt, obj['score'])
                    task:insert_result('YOMI_VIRUS', 1, 'Virus found from Yomi')
                else
                    rspamd_logger.infox(task, '%s: file is clean', rule.log_prefix, hash)
                    task:insert_result('YOMI_CLEAN', 1, 'File is clean')
                end
            end

          else
            -- not res
            rspamd_logger.errx(task, 'Yomi invalid response')
            task:insert_result('YOMI_FAIL', 1.0, 'Bad Yomi reply: ' .. json_err)
            return
          end
        end

      end

  end

  request_data.callback = yhash_http_callback
  http.request(request_data)

end

return {
  type = 'antivirus',
  description = 'Yomi sandbox integration',
  configure = yomi_config,
  check = yomi_check,
  name = N
}

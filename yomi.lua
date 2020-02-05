local lua_util = require "lua_util"
local http = require "rspamd_http"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'yomi'

local function yomi_config(opts)

  local default_conf = {
    name = N,
    url = "http://127.0.0.1:5000",
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

local function yomi_check(task, content, digest, rule)
  local function yomi_check_uncached()
    local function make_url(hash)
      return string.format('%s/hash/%s',
          rule.url, hash)
    end

    local hash = rspamd_cryptobox_hash.create_specific('sha256')
    hash:update(content)
    hash = hash:hex()

    local url = make_url(hash)
    lua_util.debugm(N, task, "send request %s", url)
    local request_data = {
      task = task,
      url = url,
      timeout = rule.timeout,
    }

    local function vt_http_callback(http_err, code, body, headers)
      if http_err then
        rspamd_logger.errx(task, 'HTTP error: %s, body: %s, headers: %s', http_err, body, headers)
      else
        local cached
        local dyn_score
        -- Parse the response
        if code ~= 200 then
          if code == 404 then
            cached = 'OK'
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s: hash %s clean (not found)',
                  rule.log_prefix, hash)
            else
              lua_util.debugm(rule.name, task, '%s: hash %s clean (not found)',
                  rule.log_prefix, hash)
            end
          elseif code == 204 then
            -- Request rate limit exceeded
            rspamd_logger.infox(task, 'yomi request rate limit exceeded')
            task:insert_result(rule.symbol_fail, 1, 'rate limit exceeded')
            return
          else
            rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
            task:insert_result(rule.symbol_fail, 1, 'Bad HTTP code: ' .. code)
            return
          end
        else
          local ucl = require "ucl"
          local parser = ucl.parser()
          local res,json_err = parser:parse_string(body)

          lua_util.debugm(rule.name, task, '%s: got reply data: "%s"',
              rule.log_prefix, body)

          if res then
            local obj = parser:get_object()
            if not obj.score or type(obj.score) ~= 'number' then
              if obj.response_code then
                if obj.response_code == 0 then
                  cached = 'OK'
                  if rule['log_clean'] then
                    rspamd_logger.infox(task, '%s: hash %s clean (not found)',
                        rule.log_prefix, hash)
                  else
                    lua_util.debugm(rule.name, task, '%s: hash %s clean (not found)',
                        rule.log_prefix, hash)
                  end
                else
                  rspamd_logger.errx(task, 'invalid JSON reply: %s, body: %s, headers: %s',
                      'bad response code: ' .. tostring(obj.response_code), body, headers)
                  task:insert_result(rule.symbol_fail, 0, 'Bad JSON reply: no `score` elements')
                  return
                end
              else
                rspamd_logger.errx(task, 'invalid JSON reply: %s, body: %s, headers: %s',
                    'no response_code', body, headers)
                task:insert_result(rule.symbol_fail, 0, 'Bad JSON reply: no `score` elementa')
                return
              end
            local sopt = string.format("%s : score : %s",
                    hash, obj.score, dyn_score)
                common.yield_result(task, rule, sopt, dyn_score)
                cached = sopt
              end
          else
            -- not res
            rspamd_logger.errx(task, 'invalid JSON reply: %s, body: %s, headers: %s',
                json_err, body, headers)
            task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: ' .. json_err)
            return
          end
        end

        if cached then
          common.save_cache(task, digest, rule, cached, dyn_score)
        end
      end
    end

    request_data.callback = vt_http_callback
    http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      yomi_check_uncached) then
    return
  else

    yomi_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'Yoroi integration',
  configure = yomi_config,
  check = yomi_check,
  name = N
}


local cjson_safe = require "cjson.safe"
local http = require "resty.http"
local jwt = require "resty.jwt"

-- string interpolation with named parameters in table
local function interp(s, tab)
    return (s:gsub('($%b{})', function(w) return tab[w:sub(3, -2)] or w end))
end

local function tableToString(tbl, depth)
    if not depth then depth = 0 end
    if depth > 5 then return "..." end  -- Limit depth to prevent infinite recursion

    local result = "{"
    for k, v in pairs(tbl) do
        -- Format the key
        if type(k) == "string" then
            k = '"' .. k .. '"'
        end

        -- Format the value
        local value = v
        if type(v) == "table" then
            value = tableToString(v, depth + 1)
        elseif type(v) == "string" then
            value = '"' .. v .. '"'
        end

        result = result .. "[" .. k .. "] = " .. tostring(value) .. ", "
    end

    -- Remove the last comma and space if any
    if result ~= "{" then
        result = result:sub(1, -3)
    end

    return result .. "}"
end


-- slice a list
local function slice(list, from, to)
    local sliced_results = {};
    for i=from, to do
        table.insert(sliced_results, list[i]);
    end;
    return sliced_results;
end

-- split string based on delimiter
local function split(s, delimiter)
    local result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match);
    end
    return result
end

-- query "Get a Document (with Input)" endpoint from the OPA Data API
local function getDocument(input, conf)
    -- serialize the input into a string containing the JSON representation
    local json_body = assert(cjson_safe.encode({ input = input }))

    local opa_uri = interp("${protocol}://${host}:${port}/${base_path}/${decision}", {
        protocol = conf.server.protocol,
        host = conf.server.host,
        port = conf.server.port,
        base_path = conf.policy.base_path,
        decision = conf.policy.decision
    })

    local res, err = http.new():request_uri(opa_uri, {
        method = "POST",
        body = json_body,
        headers = {
          ["Content-Type"] = "application/json",
        },
        keepalive_timeout = conf.server.connection.timeout,
        keepalive_pool = conf.server.connection.pool
    })
	kong.log.err("50 OK")

    if err then
        error(err) -- failed to request the endpoint
    end
	kong.log.err("55 OK")

    -- deserialise the response into a Lua table
    return assert(cjson_safe.decode(res.body))
end

-- module
local _M = {}

local function filterHeaders(headers, wanted_headers)
    -- "Since the 0.6.9 release, all the header names in the Lua table returned
    -- are converted to the pure lower-case form by default, unless the raw
    -- argument is set to true (default to false)."
    -- So we need to convert the requested header names to lower case too.
    local filtered_headers = {}
    if wanted_headers and headers then
        for _, wanted_header in ipairs(wanted_headers) do
            local lower_key = string.lower(wanted_header)
            local value = headers[lower_key]
            if value then
                filtered_headers[lower_key] = value
            end
        end
    end
    return filtered_headers
end

function _M.execute(conf)
    local authorization = ngx.var.http_authorization

	kong.log.err("85 OK")

    -- decode JWT token
    local token = {}
    if authorization and string.find(authorization, "Bearer") then
        local encoded_token = authorization:gsub("Bearer ", "")
        token = jwt:load_jwt(encoded_token)
    end

    local list_path = split(ngx.var.upstream_uri, "/")
    local split_path = slice(list_path, 2, #list_path)
    local querystring = kong.request.get_query()

    -- input document that will be send to opa
    local input = {
        token = token,
        method = ngx.var.request_method,
        path = ngx.var.upstream_uri,
        split_path = split_path,
        querystring = querystring,
        headers = filterHeaders(ngx.req.get_headers(), conf.document and conf.document.include_headers)
    }

    local status, res = pcall(getDocument, input, conf)
    kong.log.err(status)
    kong.log.err(res)
    kong.log.err(res.result)
    kong.log.err(tableToString(res.result))

    if not status then
        kong.log.err("Failed to get document: ", res)
        return kong.response.exit(500, { message = "Oops, something went wrong", error_code = "ERROR_CODE_2000" })
    end

    -- when the policy fail, 'result' is omitted
    if not res.result then
        kong.log.info("Access forbidden")
        return kong.response.exit(403, { message = "Access Forbidden", error_code = "ERROR_CODE_UNAUTHORIZED" })
    end

    -- access allowed
    kong.log.debug(interp("Access allowed to ${method} ${path} for user ${subject}", {
        method = input.method,
        path = input.path,
        subject = (token.payload and token.payload.sub or 'anonymous')
    }))
end

return _M

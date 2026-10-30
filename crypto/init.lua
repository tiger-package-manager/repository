local openssl = require("openssl")

local crypto = {}

local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function crypto.b64_encode(data)
    if openssl.base64 then return openssl.base64(data, true) end
    return ((data:gsub('.', function(x)
        local r, byte = '', x:byte()
        for i = 8, 1, -1 do r = r .. (byte % 2 ^ i - byte % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c = 0
        for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
        return b:sub(c + 1, c + 1)
    end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

function crypto.b64_decode(str)
    str = str:gsub('[^' .. b .. '=]', '')
    return (str:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) end
        return string.char(c)
    end))
end

function crypto.b64url_encode(data)
    local b64 = crypto.b64_encode(data)
    return b64:gsub("%+", "-"):gsub("/", "_"):gsub("=", "")
end

function crypto.b64url_decode(str)
    str = str:gsub("-", "+"):gsub("_", "/")
    local pad = #str % 4
    if pad > 0 then str = str .. string.rep("=", 4 - pad) end
    return crypto.b64_decode(str)
end

function crypto.hmac_sha256(data, secret)
    if type(openssl.hmac) == "table" and openssl.hmac.digest then
        return openssl.hmac.digest("sha256", data, secret, true)
    else
        return openssl.hmac("sha256", secret, data, true)
    end
end

function crypto.randomBytes(size)
    return openssl.random(size)
end

return crypto

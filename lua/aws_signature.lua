local digest = require("openssl.digest")
local hmac = require("openssl.hmac")

function string:fromhex()
    return (self:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function string:tohex()
    return (self:gsub('.', function (c)
        return string.format('%02x', string.byte(c))
    end))
end

function hmac_sha256(key, message)
    local h = hmac.new(key, "SHA256")
    return h:final(message)
end

function digest_sha256(message)
    local d = digest.new("SHA256")
    return d:final(message)
end

function canonicalRequest(method, uri, query_string, headers, signed_headers, payload, epoch)
    local hashed_payload = hashedPayload(payload)

    -- add x-amz-content-sha256 header
    headers["x-amz-content-sha256"] = hashed_payload
    table.insert(signed_headers, "x-amz-content-sha256")

    -- add x-amz-date header
    headers["x-amz-date"] = os.date("!%Y%m%dT%H%M%SZ", epoch)
    table.insert(signed_headers, "x-amz-date")

    table.sort(signed_headers)

    return method .. "\n"
        .. canonicalUri(uri) .. "\n"
        .. canonicalQueryString(query_string) .. "\n"
        .. canonicalHeaders(headers, signed_headers) .. "\n"
        .. signedHeaders(signed_headers) .. "\n"
        .. hashed_payload
end

function canonicalUri(uri)
    return uri
end

function canonicalQueryString(query_string)
    return "" -- TODO(andrein): problem for tomorrow's me
end

function canonicalHeaders(headers, signed_headers)
    result = ""
    for _, header in ipairs(signed_headers) do
        result = result .. header .. ":" .. headers[header] .. "\n"
    end
    return result
end

function signedHeaders(headers)
    return table.concat(headers, ";")
end

function hashedPayload(payload)
    if payload == "" or payload == nil then
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    end
    return digest_sha256(payload):tohex()
end

function scope(epoch, region, service)
    return os.date("!%Y%m%d", epoch) .. "/" .. region .. "/" .. service .. "/aws4_request"
end

function stringToSign(scope, canonical_request, epoch)
    return "AWS4-HMAC-SHA256" .. "\n"
        .. os.date("!%Y%m%dT%H%M%SZ", epoch) .. "\n"
        .. scope .. "\n"
        .. digest_sha256(canonical_request):tohex()
end

function signingKey(epoch, secret_key, region, service)
    local alg = "SHA256"

    local date_key = hmac_sha256("AWS4" .. secret_key, os.date("!%Y%m%d", epoch))
    local date_region_key = hmac_sha256(date_key, region)
    local date_region_service_key = hmac_sha256(date_region_key, service)
    return hmac_sha256(date_region_service_key, "aws4_request")
end

function signature(signing_key, string_to_sign)
    return hmac_sha256(signing_key, string_to_sign):tohex()
end

function authorizationHeader(access_key, scope, signed_headers, signature)
    return "AWS4-HMAC-SHA256 Credential=" .. access_key .. "/" .. scope .. ",SignedHeaders=" .. signed_headers .. ",Signature=" .. signature
end

-- if we're running in Haproxy, register our action
if core then
    function sign_s3(txn, access_key, secret_key, bucket, region, endpoint)
        local service = "s3"
        local epoch = core.now().sec

        local supported_methods = {
            ["GET"] = true,
            ["HEAD"] = true,
            ["OPTIONS"] = true,
            ["TRACE"] = true
        }

        local method = txn.sf:method()
        if supported_methods[method] == nil then
            if not pcall(function () txn:done{ status = 405} end) then
                return -- txn:done() only supports the reply parameter in Haproxy 2.2+
            end
            return
        end

        local uri = txn.sf:capture_req_uri()

        -- remove the query string
        txn.http:req_set_query("")

        txn.http:req_set_header("host", bucket .. "." .. endpoint)
        local query_string = {}
        local signed_headers = {"host"}

        local headers = {}
        for header, values in pairs(txn.http:req_get_headers()) do
            headers[header] = table.concat(values, ",", 0)
        end

        local payload = "" -- GET/HEAD has empty payload

        -- TODO(andrein): canonical_request has side effects, and we're abusing them here
        local canonical_request = canonicalRequest(method, uri, query_string, headers, signed_headers, payload, epoch)
        for _, header in ipairs(signed_headers) do
            txn.http:req_set_header(header, headers[header])
        end

        local scope = scope(epoch, region, service)
        local string_to_sign = stringToSign(scope, canonical_request, epoch)
        local signing_key = signingKey(epoch, secret_key, region, service)
        local signature = signature(signing_key, string_to_sign)
        txn.http:req_add_header("Authorization", authorizationHeader(access_key, scope, signedHeaders(signed_headers), signature, epoch))
    end

    core.register_action("sign_s3", {"http-req"}, sign_s3, 5)
end
local luaunit = require('luaunit')

require('aws_signature')

function TestStringToHex()
    local s = "test"
    luaunit.assertEquals(s:tohex(), "74657374")
end

function TestStringFromHex()
    local h = "74657374"
    luaunit.assertEquals(h:fromhex(), "test")
end

-- https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-calculations

function TestCanonicalRequest()
    local epoch = 1369353600 -- 20130524T000000Z (Fri, 24 May 2013 00:00:00 GMT)
    local method = "GET"
    local uri = "/test.txt"
    local query_string = {}
    local headers = {
        ["host"] = "examplebucket.s3.amazonaws.com",
        ["range"] = "bytes=0-9"
    }
    local signed_headers = {"host", "range"}
    local payload = ""

    local expected = [[
GET
/test.txt

host:examplebucket.s3.amazonaws.com
range:bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20130524T000000Z

host;range;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]]

    luaunit.assertEquals(canonicalRequest(method, uri, query_string, headers, signed_headers, payload, epoch), expected)
end

function TestHashedPayload()
    luaunit.assertEquals(hashedPayload(nil), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    testCases = {
        [""] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ["123"] = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
        ["abc"] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    }

    for k, v in pairs(testCases) do
        luaunit.assertEquals(hashedPayload(k), v)
    end
end

function TestScope()
    local epoch = 1440892800 -- 20150830 (Sunday, August 30, 2015 0:00:00)
    local region = "us-east-1"
    local service = "iam"

    local expected = "20150830/us-east-1/iam/aws4_request"

    luaunit.assertEquals(scope(epoch, region, service), expected)
end

function TestStringToSign()
    local scope = "20130524/us-east-1/s3/aws4_request"
    local canonical_request = [[
GET
/test.txt

host:examplebucket.s3.amazonaws.com
range:bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20130524T000000Z

host;range;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]]
    local epoch = 1369353600 -- 20130524T000000Z (Fri, 24 May 2013 00:00:00 GMT)

    local expected = [[
AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972]]
    luaunit.assertEquals(stringToSign(scope, canonical_request, epoch), expected)
end

function TestSigningKey()
    -- https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-other
    local epoch = 1329264000 -- 20120215 (Wednesday, February 15, 2012 0:00:00)
    local key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    local region = "us-east-1"
    local service = "iam"

    local actual = signingKey(epoch, key, region, service):tohex()
    local expected = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
    luaunit.assertEquals(actual, expected)
end

-- TODO(andrein) remove dependency on signing_key
function TestSignature()
    local signing_key = ("dbb893acc010964918f1fd433add87c70e8b0db6be30c1fbeafefa5ec6ba8378"):fromhex()
    local string_to_sign = [[
AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972]]

    local expected = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"

    luaunit.assertEquals(signature(signing_key, string_to_sign), expected)
end

function TestAuthorizationHeader()
    local access_key = "AKIAIOSFODNN7EXAMPLE"
    local region = "us-east-1"
    local service = "s3"
    local signed_headers = {"host", "range", "x-amz-content-sha256", "x-amz-date"} -- TODO(andrein) fix this
    local signature = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    local epoch = 1369353600 -- 20130524T000000Z (Fri, 24 May 2013 00:00:00 GMT)

    local actual = authorizationHeader(access_key, scope(epoch, region, service), signedHeaders(signed_headers), signature, epoch)
    local expected = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"

    luaunit.assertEquals(actual, expected)
end

os.exit( luaunit.LuaUnit.run() )
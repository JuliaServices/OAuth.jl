using OAuth
using FactCheck

facts("oauth_timestamp") do
    context("returns a string") do
        @fact typeof(oauth_timestamp()) <: AbstractString --> true
    end

    context("returns a value representing a time after 2014-01-25 20:25:00") do
        @fact parse(Int, oauth_timestamp()) > 1422235471 --> true
    end
end

facts("ouath_nonce") do
    context("returns a string") do
        @fact typeof(oauth_nonce(15)) <: AbstractString --> true
    end

    context("with a length equal to the parameter length") do
        @fact length(oauth_nonce(15)) --> 15
        @fact length(oauth_nonce(20)) --> 20
        @fact length(oauth_nonce(25)) --> 25
        @fact length(oauth_nonce(30)) --> 30
        @fact length(oauth_nonce(32)) --> 32
    end
end

facts("oauth_sign_hmac_sha1") do
    context("provides a consistent string") do
        expected = "WqKCG5iyhFiES3fWYVdWJWwinaY="
        @fact oauth_sign_hmac_sha1("randy", "zwitch") --> expected
    end
end

facts("oauth_signing_key") do
    context("returns a concatenation of values, seperated by &") do
        result = oauth_signing_key("9djdj82h48djs9d2", "kkk9d7dh3k39sjv7")
        expected = "9djdj82h48djs9d2&kkk9d7dh3k39sjv7"
        @fact result --> expected
    end
end

facts("oauth_signature_base_string") do
    context("returns a concatinated and percent-encoded string") do
        result = oauth_signature_base_string(
            "POST", "http://example.com", "?julia=fast&lang=elegant"
        )
        expected = "POST&http%3A%2F%2Fexample.com&%3Fjulia%3Dfast%26lang%3Delegant"
        @fact result --> expected
    end
end

facts("oauth_percent_encode_keys!") do
    context("replaces un-encoded keys with their encoded versions") do
        params   = Dict("badkey!"   => "value", "goodkey" => "value")
        expected = Dict("badkey%21" => "value", "goodkey" => "value")

        @fact oauth_percent_encode_keys!(params) --> expected
    end
end

facts("oauth_serialize_url_parameters") do
    context("returns an & concatinated string of key=value") do
        params = Dict("language" => "julia", "result" => "awesome")
        expected = "language=julia&result=awesome"
        @fact oauth_serialize_url_parameters(params) --> expected
    end
end

facts("encodeURI!") do
    context("escapes all values in the parameters that are strings") do
        params   = Dict("iv" => 10, "s" => "value!")
        expected = Dict("iv" => 10, "s" => "value%21")

        @fact encodeURI!(params) --> expected
    end
end

facts("oauth_body_hash_encode") do
    context("returns the base64 encoded SHA1 digest of the data") do
        result = oauth_body_hash_encode("Hello, World!")
        expected = "CgqfKmdylCVXq1NV12r0Qvj2XgE="
        @fact result --> expected
    end
end

facts("oauth_body_hash_data") do
    context("returns a string of the oauth_body_hash key-value pair ") do
        result = oauth_body_hash_data("Hello, World!")
        encoded_hash = "CgqfKmdylCVXq1NV12r0Qvj2XgE="
        expected = "oauth_body_hash=$encoded_hash"

        @fact result --> expected
    end
end

facts("oauth_body_hash_file") do
    context("returns a string of the oauth_body_hash key-value pair ") do
        test_file = joinpath(dirname(@__FILE__), "auth_body_hash_file.txt")
        result = oauth_body_hash_file(test_file)
        encoded_hash = "CgqfKmdylCVXq1NV12r0Qvj2XgE="
        expected = "oauth_body_hash=$encoded_hash"

        @fact result --> expected
    end
end


#TODO
#oauth_header()



#TODO
#oauth_request_resource()


FactCheck.exitstatus()

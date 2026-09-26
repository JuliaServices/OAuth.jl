using Test, Dates, OAuth
using OAuth: HTTP

@testset "DPoP replay lifetime" begin
    fixtures = joinpath(pkgdir(OAuth), "test", "fixtures")
    start = DateTime(2026, 9, 26, 12)
    client = OAuth.DPoPAuth(
        private_key=read(joinpath(fixtures, "ec_private.pem"), String),
        public_jwk=Dict(
            "kty"=>"EC", "crv"=>"P-256",
            "x"=>"cp-fRlYuifWF9f3bsGBq3t5xueGOdsZ0vFSQRqrdJ2Y",
            "y"=>"5iaMGjmGzt5OiwUyK6GaMcMIm-IUrO5YbB0MxouBbew",
        ), iat_skew=0,
    )
    issuer = OAuth.JWTAccessTokenIssuer(
        issuer="https://id.example.com", audience=["https://api.example.com"],
        private_key=read(joinpath(fixtures, "rsa_private.pem"), String),
    )
    validator = OAuth.TokenValidationConfig(
        issuer="https://id.example.com", audience=["https://api.example.com"],
        jwks=Dict("keys"=>[OAuth.public_jwk(issuer)]),
    )
    token_for(auth, t) = OAuth.issue_access_token(issuer;
        subject="fixture-user", confirmation_jkt=OAuth.dpop_thumbprint(auth), now=t)
    token = token_for(client, start)
    claims = OAuth.validate_jwt_access_token(token.token, validator; now=start)
    req = HTTP.Request("GET", "/resource")
    origin = OAuth.ResourceOrigin("https://api.example.com")
    function proof_at(t, jti; auth=client, access_token=token.token, method="GET", nonce=nothing)
        proof = OAuth.create_dpop_proof(auth, method, "https://api.example.com/resource", t; access_token, nonce)
        header, payload, _, _ = OAuth.decode_compact_jwt(proof)
        payload["jti"] = jti
        return OAuth.build_jws_compact(Dict{String,Any}(header), payload, auth.signer, auth.alg)
    end
    function result(cache, proof, t; age=300, skew=60, token_claims=claims, nonce_validator=nothing)
        try
            OAuth.verify_dpop_proof(proof, req, token_claims, origin, cache, t, Second(age), Second(skew), nonce_validator)
            return "accepted"
        catch err
            err isa OAuth.OAuthError || rethrow()
            return err.message
        end
    end

    @testset "retain every accepted proof through its inclusive expiry" begin
        for (window, age, skew, issued_offset) in (
            (300, 300, 60, 60), (1, 300, 60, 0), (1000, 300, 60, 60),
            (1, 0, 60, 60), (300, 300, 0, 0), (1, 300, 0, -300),
        )
            cache = OAuth.DPoPReplayCache(window_seconds=window)
            issued = start + Second(issued_offset)
            proof = proof_at(issued, "shared-id")
            @test result(cache, proof, start; age, skew) == "accepted"
            @test result(cache, proof, start; age, skew) == "DPoP proof replay detected"
            expiry = issued + Second(age)
            for t in sort!([start + Second(window) + Millisecond(1), expiry])
                expected = t <= expiry ? "DPoP proof replay detected" : "DPoP proof expired"
                @test result(cache, proof, t; age, skew) == expected
            end
            @test result(cache, proof, expiry + Millisecond(1); age, skew) == "DPoP proof expired"
            # A newly signed proof can reuse an ID after both retention bounds end.
            later = max(start + Second(window), expiry) + Second(1)
            @test result(cache, proof_at(later, "shared-id"), later; age, skew) == "accepted"
        end
    end

    @testset "time and invalid-proof boundaries" begin
        for (offset, t, skew, expected) in (
            (-300, start, 60, "accepted"),
            (-300, start + Millisecond(1), 60, "DPoP proof expired"),
            (60, start, 60, "accepted"),
            (61, start, 60, "DPoP proof issued in the future"),
            (0, start, 0, "accepted"),
            (1, start, 0, "DPoP proof issued in the future"),
        )
            cache = OAuth.DPoPReplayCache()
            @test result(cache, proof_at(start + Second(offset), "boundary"), t; skew) == expected
        end
        cache = OAuth.DPoPReplayCache()
        proof = proof_at(start, "clock-movement")
        @test result(cache, proof, start + Millisecond(500)) == "accepted"
        @test result(cache, proof, start - Second(30)) == "DPoP proof replay detected"
        @test result(cache, proof, start + Second(300)) == "DPoP proof replay detected"
        @test result(cache, proof, start + Second(300) + Millisecond(1)) == "DPoP proof expired"

        cache = OAuth.DPoPReplayCache()
        @test result(cache, proof_at(start, "valid-after-invalid"; method="POST"), start) == "DPoP htm mismatch"
        proof = proof_at(start, "valid-after-invalid"; nonce="fixture-nonce")
        @test result(cache, proof, start; nonce_validator=(_, _) -> false) == "DPoP proof nonce invalid"
        @test isempty(cache.entries)
        @test result(cache, proof, start; nonce_validator=(_, _) -> true) == "accepted"

        cache = OAuth.DPoPReplayCache()
        proof = proof_at(start, "valid-after-bad-signature")
        _, _, signature, signing_input = OAuth.decode_compact_jwt(proof)
        signature[1] ⊻= 0x01
        invalid_proof = String(signing_input) * "." * OAuth.base64url(signature)
        @test result(cache, invalid_proof, start) == "Invalid DPoP proof signature"
        @test isempty(cache.entries)
        @test result(cache, proof, start) == "accepted"
    end

    @testset "configured retention and atomic recording" begin
        cache = OAuth.DPoPReplayCache(window_seconds=1000)
        proof = proof_at(start, "retained-id")
        @test result(cache, proof, start) == "accepted"
        # A new proof with the same ID remains rejected for a longer configured window.
        later = start + Second(500)
        @test result(cache, proof_at(later, "retained-id"), later) == "DPoP proof replay detected"
        @test OAuth.record_dpop_proof!(cache, "private-helper", start)
        @test !OAuth.record_dpop_proof!(cache, "private-helper", start + Second(1000))
        @test OAuth.record_dpop_proof!(cache, "private-helper", start + Second(1000) + Millisecond(1))
        @test_throws ArgumentError OAuth.DPoPReplayCache(window_seconds=0)
        @test_throws ArgumentError OAuth.DPoPReplayCache(window_seconds=-1)

        cache = OAuth.DPoPReplayCache()
        proof = proof_at(start + Second(60), "concurrent-id")
        ready = Channel{Nothing}(16)
        gate = Base.Event()
        tasks = [Threads.@spawn begin
            put!(ready, nothing)
            wait(gate)
            result(cache, proof, start)
        end for _ in 1:16]
        for _ in tasks
            take!(ready)
        end
        notify(gate)
        outcomes = fetch.(tasks)
        @test count(==("accepted"), outcomes) == 1
        @test count(==("DPoP proof replay detected"), outcomes) == 15
        @test result(cache, proof, start + Second(301)) == "DPoP proof replay detected"
    end

    @testset "cache-wide IDs retain their existing key scope" begin
        other_jwk = OAuth.public_jwk(issuer)
        other_token = OAuth.issue_access_token(issuer; subject="other-fixture-user",
            confirmation_jkt=OAuth.jwk_thumbprint(other_jwk), now=start)
        other_claims = OAuth.validate_jwt_access_token(other_token.token, validator; now=start)
        proof = proof_at(start, "same-id")
        header, payload, _, _ = OAuth.decode_compact_jwt(proof)
        header["jwk"] = other_jwk
        header["alg"] = "RS256"
        payload["ath"] = OAuth.base64url(OAuth.SHA.sha256(codeunits(other_token.token)))
        other_proof = OAuth.build_jws_compact(Dict{String,Any}(header), payload, issuer.signer, :RS256)
        cache = OAuth.DPoPReplayCache()
        @test result(cache, proof, start) == "accepted"
        @test result(cache, other_proof, start; token_claims=other_claims) == "DPoP proof replay detected"
        @test result(OAuth.DPoPReplayCache(), other_proof, start; token_claims=other_claims) == "accepted"
    end

    @testset "protected resource honors the proof lifetime with a short cache" begin
        now = Dates.now(UTC)
        live_token = token_for(client, now)
        live_claims = OAuth.validate_jwt_access_token(live_token.token, validator; now)
        proof = proof_at(now, "middleware-replay"; access_token=live_token.token)
        cache = OAuth.DPoPReplayCache(window_seconds=1)
        @test result(cache, proof, now - Second(2); token_claims=live_claims) == "accepted"
        handled = Ref(0)
        handler = OAuth.protected_resource_middleware(
            _ -> (handled[] += 1; HTTP.Response(200, "ok")), validator;
            resource_metadata_url="https://api.example.com", dpop_replay_cache=cache)
        request(p) = HTTP.Request("GET", "/resource", ["Authorization"=>"DPoP $(live_token.token)", "DPoP"=>p])
        @test handler(request(proof)).status == 401
        @test handled[] == 0
        fresh = proof_at(now, "middleware-fresh"; access_token=live_token.token)
        @test handler(request(fresh)).status == 200
        @test handled[] == 1
        @test handler(request(fresh)).status == 401
    end
end

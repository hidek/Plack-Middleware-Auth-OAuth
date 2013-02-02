use strict;
use warnings;

use Test::More;
use Plack::Test;
use Plack::Middleware::Auth::OAuth;
use HTTP::Request::Common;
use OAuth::Lite::Consumer;
use Data::Dumper;
local $Data::Dumper::Terse  = 1;
local $Data::Dumper::Purity = 1;

my $public_key = <<__END_OF_PUBLIC__;
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAN4jFZ1OxLALdJcirP0eQ0ydoZ8Dc3yc/UfWMRP5Jc3rN0zwKSelZkog
I/cDdg/aXuZwdHFwwI2rfqrptkughT3pPJqmMx8zAx1nx9CRpjhLfoFbem+wa9hc
TXHlr9JvRoRAAnbdjvHE5DT+niQzp2E/H9B4a9N3thDitC/VTSFXAgMBAAE=
-----END RSA PUBLIC KEY-----
__END_OF_PUBLIC__

my $invalid_public_key = <<__END_OF_INVALID__;
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMmsdxC0oP3E7yD9PX5vxUblyBEhUY9brNhJbJS55+8rxjBdo7iImoSd
lRxOVeest+mBRKqPrEgKYpsjiduIT0MiqHFdGR7DhYGtV1Sgn75+WoLj/S9t58wg
a5eBaoJl/UzNBxENLgWoI3TtdYiZoXFysMjqsFIqQKFo/fLCyZ3pAgMBAAE=
-----END RSA PUBLIC KEY-----
__END_OF_INVALID__

my $private_key = <<__END_OF_PRIVATE__;
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDeIxWdTsSwC3SXIqz9HkNMnaGfA3N8nP1H1jET+SXN6zdM8Ckn
pWZKICP3A3YP2l7mcHRxcMCNq36q6bZLoIU96TyapjMfMwMdZ8fQkaY4S36BW3pv
sGvYXE1x5a/Sb0aEQAJ23Y7xxOQ0/p4kM6dhPx/QeGvTd7YQ4rQv1U0hVwIDAQAB
AoGAQHpwmLO3dd4tXn1LN0GkiUWsFyr6R66N+l8a6dBE/+uJpsSDPaXN9jA0IEwZ
5eod58e2lQMEcVrZLqUeK/+RDOfVlZSVcPY0eBG+u+rxmUwPVqh9ghsC7JfdmQA6
cQ14Rf/Rmlm7N3+tF83CrlBnwaNEhvHk6cJrMSSyKRF5xFECQQD7rd23/SsWqLOP
uSSy9jkdSKadsDDbJ0pHgOaRSJ3WNgJbEwLdSu6AQwy6vB0Ell4p9ixJD4MbCW46
IBrPyKapAkEA4fNhWcaBawvVAJf33jyHdGVExkQUpo6JHkitU06g5Af++sFRo8rT
aj+ZImGFvGwGGMfNoMt9d3ttdoNKW6yH/wJARoHW84yBXb+1TjZYCarhJUsNInAR
v9OqA44hCeKGFVTcJBeXXdd4KYafMlEw7/AQQUEt9unZmOFzd+U2na9gwQJAXYPR
YsqZfahj+97po30Bwta25CgBM/4CGhqSQcxlInt8uGOSWmvznCG+S1B5fUZoL5Fi
NY6C2xSmdUpZWB/MGQJAVxI4gD+kYTYvqPqU7UEu+d68aMttqJeZUbIYd4ydMWFB
CHT/dnHG/dX4b8GOOTFz1y9r2x3Org43CQOZvDy/HA==
-----END RSA PRIVATE KEY-----
__END_OF_PRIVATE__

my %args = (
    realm           => 'example.com',
    nonce           => 'nonce',
    timestamp       => 12345,
    consumer_key    => 'dummy',
);

my %params = (
    oauth_version          => '1.0',
    oauth_signature_method => 'RSA-SHA1',
    oauth_nonce            => $args{nonce},
    oauth_timestamp        => $args{timestamp},
    oauth_consumer_key     => $args{consumer_key},
);

my $consumer = OAuth::Lite::Consumer->new(
    signature_method    => $params{oauth_signature_method},
    consumer_secret     => $private_key,
    realm           => $args{realm},
    _nonce          => $args{nonce},
    _timestamp      => $args{timestamp},
);


my $app_base = sub {
    my $env = shift;

    my %env_sub =
        map  {($_ => $env->{$_})}
        grep {/^psgix\.oauth/}
        keys %{$env};

    return [200, ['Content-Type' => 'text/plain'], [Dumper \%env_sub]];
};

subtest normal => sub {
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        consumer_secret => $public_key,
        consumer_key    => $args{consumer_key},
    );

    test_psgi $app, sub {
        my $cb = shift;

        my $res = $cb->(GET 'http://localhost/');
        is $res->code, 401;

        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        $res = $cb->($req);
        is $res->code,    200;
        my $env_sub = eval $res->content;
        ok defined $env_sub->{'psgix.oauth_realm'};
        ok $env_sub->{'psgix.oauth_params'};
        is $env_sub->{'psgix.oauth_params'}{oauth_consumer_key}, $params{oauth_consumer_key};

        ok $env_sub->{'psgix.oauth_authorized'};
    };
};

subtest invalid => sub {
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        consumer_secret => $invalid_public_key,
        consumer_key    => $args{consumer_key},
    );

    test_psgi $app, sub {
        my $cb = shift;

        my $res = $cb->(GET 'http://localhost/');
        is $res->code, 401;

        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        $res = $cb->($req);
        is $res->code, 401;
    };
};

done_testing;


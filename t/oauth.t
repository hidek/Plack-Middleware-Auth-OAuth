use strict;
use warnings;

use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use OAuth::Lite::Consumer;

my %args = (
    consumer_key    => 'abc',
    consumer_secret => 'def',
    relam           => 'example.com',
    nonce           => 'nonce',
    timestamp       => 12345,
);

my %params = (
    oauth_version          => '1.0',
    oauth_signature_method => 'HMAC-SHA1',
    oauth_consumer_key     => $args{consumer_key},
    oauth_nonce            => $args{nonce},
    oauth_timestamp        => $args{timestamp},
);

my $consumer = OAuth::Lite::Consumer->new(
    consumer_key    => $args{consumer_key},
    consumer_secret => $args{consumer_secret},
    realm           => $args{realm},
    _nonce          => $args{nonce},
    _timestamp      => $args{timestamp},
);

{
    my $app = sub {
        my $env = shift;
        ok defined $env->{'psgix.oauth_realm'};
        ok $env->{'psgix.oauth_params'};
        is $env->{'psgix.oauth_params'}{oauth_consumer_key}, $params{oauth_consumer_key};

        return [200, ['Content-Type' => 'text/plain'], ['Hello World']];
    };

    $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            'consumer_key'    => $args{consumer_key},
            'consumer_secret' => $args{consumer_secret},
            ;
        $app;
    };

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
        is $res->content, "Hello World";
    };
}

{
    my $app = sub {
        return [200, ['Content-Type' => 'text/plain'], ['Hello World']];
    };

    $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            'consumer_key'    => $args{consumer_key},
            'consumer_secret' => $args{consumer_secret},
            'check_nonce_cb'  => sub {
            return shift->{oauth_nonce} eq 'nonce' ? 1 : 0;
            };
        $app;
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        my $res = $cb->($req);
        is $res->code,    200;
    };
}

{
    my $app = sub {
        return [200, ['Content-Type' => 'text/plain'], ['Hello World']];
    };

    $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            'consumer_key'    => $args{consumer_key},
            'consumer_secret' => $args{consumer_secret},
            'check_nonce_cb'  => sub {
            return shift->{oauth_timestamp} ne 12345 ? 1 : 0;
            };
        $app;
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        my $res = $cb->($req);
        is $res->code,    401;
    };
}


done_testing;


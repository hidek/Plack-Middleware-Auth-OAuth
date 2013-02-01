use strict;
use warnings;

use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use OAuth::Lite::Consumer;
use JSON;

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


my $json = JSON->new->utf8;
my $app_base = sub {
    my $env = shift;

    my %hash =
        map  {($_ => $env->{$_})}
        grep {/^psgix\.oauth/}
        keys %{$env};

    return [200, ['Content-Type' => 'text/plain'], [$json->encode(\%hash)]];
};

subtest normal => sub {
    my $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            'consumer_key'    => $args{consumer_key},
            'consumer_secret' => $args{consumer_secret},
            ;
        $app_base;
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
        my $env = $json->decode($res->content);

        ok defined $env->{'psgix.oauth_realm'};
        ok $env->{'psgix.oauth_params'};
        is $env->{'psgix.oauth_params'}{oauth_consumer_key}, $params{oauth_consumer_key};

        ok $env->{'psgix.oauth_authorized'};
    };
};

subtest check_nonce_cb => sub {
    my $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            'consumer_key'    => $args{consumer_key},
            'consumer_secret' => $args{consumer_secret},
            'check_nonce_cb'  => sub {
                return shift->{oauth_nonce} eq 'nonce' ? 1 : 0;
            };
        $app_base;
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
};

subtest check_nonce_cb_error => sub {
    my $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            'consumer_key'    => $args{consumer_key},
            'consumer_secret' => $args{consumer_secret},
            'check_nonce_cb'  => sub {
                return shift->{oauth_timestamp} ne 12345 ? 1 : 0;
            };
        $app_base;
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
};

subtest unauthorized_cb => sub {
    my $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            consumer_key    => $args{consumer_key},
            consumer_secret => $args{consumer_secret},
            unauthorized_cb => sub {
                my $env = shift;
                isa_ok $env, 'HASH';
                my $body = 'forbidden';
                return [
                    403,
                    [
                        'Content-Type'    => 'text/plain',
                        'Content-Lentgth' => length $body,
                    ],
                    [$body],
                ];
            },
        ;
        $app_base;
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET 'http://localhost/');

        is $res->code, 403;
        is $res->content, 'forbidden';
    };
};

subtest validate_only => sub {
    my $app = builder {
        enable 'Plack::Middleware::Auth::OAuth',
            consumer_key    => $args{consumer_key},
            consumer_secret => $args{consumer_secret},
            validate_only   => 1,
        ;
        $app_base;
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET 'http://localhost/');

        is $res->code, 200;
        my $env = $json->decode($res->content);
        ok !$env->{'psgix.oauth_authorized'};
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET 'http://localhost/');

        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        my $res = $cb->($req);
        my $env = $json->decode($res->content);
        ok $env->{'psgix.oauth_authorized'};
        is $res->code,    200;
    };
};

done_testing;

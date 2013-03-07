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
        consumer_key    => $args{consumer_key},
        consumer_secret => $args{consumer_secret},
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

subtest check_nonce_cb => sub {
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        consumer_key    => $args{consumer_key},
        consumer_secret => $args{consumer_secret},
        check_nonce_cb  => sub {
            return shift->{oauth_nonce} eq 'nonce' ? 1 : 0;
        },
    );

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
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        consumer_key    => $args{consumer_key},
        consumer_secret => $args{consumer_secret},
        check_nonce_cb  => sub {
            return shift->{oauth_timestamp} ne 12345 ? 1 : 0;
        },
    );

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
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        consumer_key    => $args{consumer_key},
        consumer_secret => $args{consumer_secret},
        unauthorized_cb => sub {
            my $env_sub = shift;
            isa_ok $env_sub, 'HASH';
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
    );

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET 'http://localhost/');

        is $res->code, 403;
        is $res->content, 'forbidden';
    };
};

subtest validate_only => sub {
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        consumer_key    => $args{consumer_key},
        consumer_secret => $args{consumer_secret},
        validate_only   => 1,
    );

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET 'http://localhost/');

        is $res->code, 200;
        my $env_sub = eval $res->content;
        ok !$env_sub->{'psgix.oauth_authorized'};
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        my $res = $cb->($req);
        my $env_sub = eval $res->content;
        ok $env_sub->{'psgix.oauth_authorized'};
        is $res->code,    200;
    };
};

subtest secret_resolver_cb => sub {
    my $app = Plack::Middleware::Auth::OAuth->wrap($app_base,
        secret_resolver_cb => sub {
            my $key = shift;
            $key eq $args{consumer_key} ? $args{consumer_secret} : 'hogeeeee';
        },
    );

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET 'http://localhost/');

        is $res->code, 401;
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $req = $consumer->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => \%params,
        );
        my $res = $cb->($req);
        my $env_sub = eval $res->content;
        ok $env_sub->{'psgix.oauth_authorized'};
        is $res->code,    200;
    };


    my $consumer2 = OAuth::Lite::Consumer->new(
        consumer_key    => $args{consumer_key},
        consumer_secret => 'falsefalse',
        realm           => $args{realm},
        _nonce          => $args{nonce},
        _timestamp      => $args{timestamp},
    );

    test_psgi $app, sub {
        my $cb  = shift;
        my $req = $consumer2->gen_oauth_request(
            method => 'GET',
            url    => 'http://localhost/',
            params => {
                %params,
            },
        );
        my $res = $cb->($req);
        my $env_sub = eval $res->content;
        is $res->code,    401;
    };

};

done_testing;

use strict;
use warnings;

use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;

my $app = sub {
    return [200, ['Content-Type' => 'text/plain'], ['Hello World']];
};

my %args = (
    consumer_key    => 'abc',
    consumer_secret => 'def',
    app             => 12345,
    viewer          => 123,
    owner           => 456,
);

$app = builder {
    enable 'Auth::OAuth',
        'consumer_key'    => $args{consumer_key},
        'consumer_secret' => $args{consumer_secret},
        ;
    $app;
};

test_psgi $app, sub {
    my $cb = shift;

    my $res = $cb->(GET 'http://localhost/');
    is $res->code, 401;

    my $req = GET
        "http://localhost/?opensocial_app_id=$args{app}&opensocial_viewer_id=$args{viewer}&opensocial_owner_id=$args{owner}",
        "Authorization" =>
        'OAuth realm="",oauth_consumer_key="abc",oauth_nonce="nonce",oauth_signature="7SPPfyW3ozFbP6cgoK7157hiLTE=",oauth_signature_method="HMAC-SHA1",oauth_timestamp="12345",oauth_version="1.0"';
    $res = $cb->($req);
    is $res->code,    200;
    is $res->content, "Hello World";
};

done_testing;

